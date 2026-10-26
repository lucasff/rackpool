// mp is the member CLI: add files, list the library, read files back, serve
// the library over HTTP for a media server, and show pool status.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/client"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

const usage = `usage: mp [-coord URL] <command> [args]

  add <file> <pool-path> [-torrent INFOHASH -torrent-file PATH]
  rm <pool-path>               remove a file you added
  ls
  cat <pool-path>              write a file to stdout
  serve [-listen :8080]        HTTP server with range requests (point Jellyfin/VLC here)
  status

  keygen <file>                write a new private key, print its public key

The pool secret is read from $MEDIAPOOL_SECRET. -pool, -member and -key
identify you to the pool.`

func main() {
	coordURL := flag.String("coord", "http://127.0.0.1:7000", "coordinator URL")
	poolPath := flag.String("pool", "pool.json", "pool membership file")
	member := flag.String("member", os.Getenv("MEDIAPOOL_MEMBER"), "your member name in the pool file")
	keyPath := flag.String("key", "member.key", "your private key")
	catPath := flag.String("catalog", "", "local catalog replica (default: memory only)")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	cmd, args := flag.Arg(0), flag.Args()[1:]
	if cmd == "keygen" {
		if len(args) != 1 {
			log.Fatal("keygen <file>")
		}
		k, err := auth.LoadOrCreateKey(args[0])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(auth.PubHex(k))
		return
	}
	secret := os.Getenv("MEDIAPOOL_SECRET")
	if secret == "" {
		log.Fatal("MEDIAPOOL_SECRET is not set")
	}
	pool, err := auth.LoadPool(*poolPath)
	if err != nil {
		log.Fatal(err)
	}
	key, err := auth.LoadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(*coordURL, []byte(secret), *member, key, pool, *catPath)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()

	switch cmd {
	case "add":
		err = add(ctx, c, args)
	case "rm":
		if len(args) != 1 {
			err = errors.New("rm <pool-path>")
		} else {
			err = c.Remove(ctx, args[0])
		}
	case "ls":
		err = ls(ctx, c)
	case "cat":
		err = cat(ctx, c, args)
	case "serve":
		err = serve(ctx, c, args)
	case "status":
		err = status(ctx, *coordURL, auth.NewIdentity(key))
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func add(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	infohash := fs.String("torrent", "", "infohash of the torrent this file came from (enables bridge repair)")
	tfile := fs.String("torrent-file", "", "path of this file inside the torrent (default: base name)")
	if len(args) < 2 {
		return errors.New("add <file> <pool-path> [flags]")
	}
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	var src *client.Source
	if *infohash != "" {
		src = &client.Source{Infohash: strings.ToLower(*infohash), File: *tfile}
		if src.File == "" {
			src.File = path.Base(args[0])
		}
	}
	st, err := c.AddFile(ctx, args[0], args[1], src)
	if err != nil {
		return err
	}
	fmt.Printf("added %s: %d segments, %d already in pool, %s uploaded for %s of content\n",
		args[1], st.Segments, st.Deduped, human(st.Uploaded), human(st.PlainSize))
	return nil
}

func ls(ctx context.Context, c *client.Client) error {
	ms, err := c.List(ctx)
	if err != nil {
		return err
	}
	for _, m := range ms {
		fmt.Printf("%10s  %-10s %s\n", human(m.Size), m.Author, m.Path)
	}
	return nil
}

func cat(ctx context.Context, c *client.Client, args []string) error {
	if len(args) != 1 {
		return errors.New("cat <pool-path>")
	}
	m, err := c.Stat(ctx, args[0])
	if err != nil {
		return err
	}
	_, err = io.Copy(os.Stdout, c.Open(ctx, m))
	return err
}

func serve(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "listen address")
	_ = fs.Parse(args)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			ms, err := c.List(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			for _, m := range ms {
				fmt.Fprintf(w, "<a href=\"%s\">%s</a> (%s)<br>\n", m.Path, m.Path, human(m.Size))
			}
			return
		}
		m, err := c.Stat(r.Context(), r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// ServeContent handles Range requests, so players can seek.
		http.ServeContent(w, r, path.Base(m.Path), noModTime, c.Open(r.Context(), m))
	})
	log.Printf("serving pool library on %s", *listen)
	return http.ListenAndServe(*listen, h)
}

func status(ctx context.Context, coordURL string, id *auth.Identity) error {
	var st proto.StatusResponse
	if err := transfer.GetJSON(ctx, http.DefaultClient, id, coordURL+"/v1/status", &st); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "catalog head %d", st.Head.Seq)
	if st.WriteBlocked != "" {
		fmt.Fprintf(tw, " (WRITES BLOCKED: %s)", st.WriteBlocked)
	}
	fmt.Fprintf(tw, "\n\nNODE\tOWNER\tONLINE\tBRIDGE\tSHARDS\tSTRIKES\tFAIL-P\n")
	for _, n := range st.Nodes {
		fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%d\t%d\t%.3f\n", n.ID, n.Owner, n.Online, n.Bridge, n.Shards, n.Strikes, n.FailProb)
	}
	fmt.Fprintf(tw, "\nSEGMENT\tCLASS\tREFS\tONLINE/DURABLE/TARGET\tLOSS-P\tHEAT(reads/min)\tREPAIRING\n")
	for _, s := range st.Segments {
		target := strconv.Itoa(s.Target)
		if s.Target == 0 {
			target = "auto"
		}
		fmt.Fprintf(tw, "%.12s\t%s\t%d\t%d/%d/%s\t%.1e\t%.1f\t%v\n", s.ID, s.Class, s.Refs, s.Online, s.Durable, target, s.LossProb, s.HeatPerMin, s.Repairing)
	}
	return tw.Flush()
}

var noModTime time.Time

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
