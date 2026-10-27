// mp is the member CLI, modelled on rclone: listing, cat, copy/move/delete,
// serving over HTTP and WebDAV, and an rc daemon with a web UI. Paths on
// the pool side are written pool:/path (the prefix is optional where only
// pool paths make sense). Every flag can also be set as MP_<FLAG>, e.g.
// MP_COORD, MP_MEMBER, MP_RC_ADDR.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"mediapool/internal/auth"
	"mediapool/internal/client"
	"mediapool/internal/limits"
	"mediapool/internal/rc"
	"mediapool/internal/stats"
	"mediapool/internal/vfs"
)

var version = "dev"

var g struct {
	coord, pool, member, key, catalog string
	verbose                           bool
	dryRun                            bool
	progress                          bool
	readAhead, cacheSize              limits.Bytes
}

func main() {
	rc.Version = version
	root := &cobra.Command{
		Use:           "mp",
		Short:         "Use a mediapool: list, read, copy, serve and control it",
		Long:          "mp is the member CLI for a mediapool. Pool paths are written pool:/path.\nEvery flag can also be set as an environment variable MP_<FLAG> (e.g. MP_COORD, MP_MEMBER).\nThe pool secret is read from $MEDIAPOOL_SECRET.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindEnv(cmd)
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&g.coord, "coord", "http://127.0.0.1:7000", "coordinator URL")
	pf.StringVar(&g.pool, "pool", "pool.json", "pool membership file")
	pf.StringVar(&g.member, "member", "", "your member name in the pool file")
	pf.StringVar(&g.key, "key", "member.key", "your private key file")
	pf.StringVar(&g.catalog, "catalog", "", "keep a local catalog replica here between runs (faster startup)")
	pf.BoolVarP(&g.verbose, "verbose", "v", false, "print more")
	pf.BoolVarP(&g.dryRun, "dry-run", "n", false, "show what would change without changing anything")
	pf.BoolVarP(&g.progress, "progress", "P", false, "show transfer progress")
	g.readAhead, g.cacheSize = limits.Bytes(client.DefaultReadAhead), limits.Bytes(client.DefaultCacheSize)
	pf.Var(&g.readAhead, "read-ahead", "how far past the segment being read to fetch in the background")
	pf.Var(&g.cacheSize, "cache-size", "memory for segments, shared by all readers of a file")

	root.AddCommand(lsCommands()...)
	root.AddCommand(catCmd(), sizeCmd(), aboutCmd(), statusCmd())
	root.AddCommand(copyCmd(false), copyCmd(true), moveCmd(), addCmd(), deleteCmd(), deletefileCmd())
	root.AddCommand(serveCmd(), rcdCmd(), rcCmd())
	root.AddCommand(keygenCmd(), poolCmd(), inviteCmd(), joinCmd(), membersCmd(), nodesCmd())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mp:", err)
		os.Exit(1)
	}
}

// bindEnv fills unset flags from MP_<FLAG> environment variables.
func bindEnv(cmd *cobra.Command) error {
	var errs []string
	set := func(f *pflag.Flag) {
		if f.Changed {
			return
		}
		name := "MP_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(name); ok {
			if err := f.Value.Set(v); err != nil {
				errs = append(errs, fmt.Sprintf("%s=%q: %v", name, v, err))
			}
		}
	}
	cmd.Flags().VisitAll(set)
	cmd.InheritedFlags().VisitAll(set)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// openFS connects as the configured member.
func openFS() (*vfs.FS, error) {
	secret := os.Getenv("MEDIAPOOL_SECRET")
	if secret == "" {
		return nil, errors.New("MEDIAPOOL_SECRET is not set")
	}
	if g.member == "" {
		return nil, errors.New("--member (MP_MEMBER) is not set")
	}
	pool, err := auth.LoadPool(g.pool)
	if err != nil {
		return nil, err
	}
	key, err := auth.LoadOrCreateKey(g.key)
	if err != nil {
		return nil, err
	}
	c, err := client.New(g.coord, []byte(secret), g.member, key, pool, g.catalog)
	if err != nil {
		return nil, err
	}
	c.ReadAhead, c.CacheSize = int64(g.readAhead), int64(g.cacheSize)
	return vfs.New(c), nil
}

var st = stats.New()

func keygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen <file>",
		Short: "Create a private key (if missing) and print its public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			k, err := auth.LoadOrCreateKey(args[0])
			if err != nil {
				return err
			}
			fmt.Println(auth.PubHex(k))
			return nil
		},
	}
}
