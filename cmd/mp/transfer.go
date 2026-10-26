package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"mediapool/internal/client"
	"mediapool/internal/vfs"
)

func isPool(p string) bool { return strings.HasPrefix(p, "pool:") }

// job is one file to transfer.
type job struct {
	src, dst string
	size     int64
	modTime  time.Time
}

type copyOpts struct {
	transfers      int
	ignoreExisting bool
	deleteSource   bool
}

func copyCmd(to bool) *cobra.Command {
	var o copyOpts
	use, short := "copy SRC DST", "Copy files between this machine and the pool, skipping unchanged ones"
	long := "One side must be pool:/path. A directory SRC is copied recursively into DST.\nFiles already at the destination with the same size and modification time are skipped."
	if to {
		use, short = "copyto SRC DST", "Copy one file to an exact destination path"
		long = "Like copy, but DST names the file itself rather than a directory to copy into."
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long, Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCopy(cmd.Context(), args[0], args[1], to, o)
		},
	}
	addCopyFlags(cmd, &o)
	return cmd
}

func moveCmd() *cobra.Command {
	var o copyOpts
	cmd := &cobra.Command{
		Use:   "move SRC DST",
		Short: "Copy, then delete each source file once it's safely at the destination",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.deleteSource = true
			return runCopy(cmd.Context(), args[0], args[1], false, o)
		},
	}
	addCopyFlags(cmd, &o)
	return cmd
}

func addCopyFlags(cmd *cobra.Command, o *copyOpts) {
	cmd.Flags().IntVar(&o.transfers, "transfers", 4, "files to transfer in parallel")
	cmd.Flags().BoolVar(&o.ignoreExisting, "ignore-existing", false, "skip files that exist at the destination, whatever their size or time")
}

func runCopy(ctx context.Context, src, dst string, exact bool, o copyOpts) error {
	if isPool(src) == isPool(dst) {
		return errors.New("exactly one of SRC and DST must be a pool:/path (copying within the pool or between local paths isn't supported)")
	}
	v, err := openFS()
	if err != nil {
		return err
	}
	var jobs []job
	if isPool(dst) {
		jobs, err = planUpload(src, vfs.Clean(dst), exact)
	} else {
		jobs, err = planDownload(ctx, v, vfs.Clean(src), dst, exact)
	}
	if err != nil {
		return err
	}
	stopProgress := startProgress()
	defer stopProgress()

	upload := isPool(dst)
	var mu sync.Mutex
	var skipped, done int
	var failed []string
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(max(1, o.transfers))
	for _, j := range jobs {
		eg.Go(func() error {
			same, err := unchanged(ctx, v, j, upload, o.ignoreExisting)
			if err != nil {
				return err
			}
			if same {
				mu.Lock()
				skipped++
				mu.Unlock()
				if g.verbose {
					fmt.Fprintf(os.Stderr, "unchanged: %s\n", j.dst)
				}
				return nil
			}
			if g.dryRun {
				fmt.Printf("would copy %s → %s (%s)\n", j.src, j.dst, human(j.size))
				return nil
			}
			if upload {
				err = uploadOne(ctx, v, j)
			} else {
				err = downloadOne(ctx, v, j)
			}
			if err == nil && o.deleteSource {
				if upload {
					err = os.Remove(j.src)
				} else {
					err = v.Remove(ctx, j.src)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", j.src, err))
				return nil // keep going; report at the end like rclone
			}
			done++
			if g.verbose {
				fmt.Fprintf(os.Stderr, "copied: %s\n", j.dst)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	stopProgress()
	snap := st.Snapshot()
	fmt.Fprintf(os.Stderr, "Transferred: %d files, %s (%s/s); unchanged: %d; errors: %d\n",
		done, human(snap.Bytes), human(int64(snap.Speed)), skipped, len(failed))
	for _, f := range failed {
		fmt.Fprintln(os.Stderr, "  error:", f)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d transfers failed", len(failed))
	}
	return nil
}

func planUpload(src, dst string, exact bool) ([]job, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		target := dst
		if !exact {
			target = path.Join(dst, filepath.Base(src))
		}
		return []job{{src: src, dst: target, size: fi.Size(), modTime: fi.ModTime()}}, nil
	}
	if exact {
		return nil, errors.New("copyto needs a file as SRC; use copy for directories")
	}
	var jobs []job
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() && p != src && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		jobs = append(jobs, job{src: p, dst: path.Join(dst, filepath.ToSlash(rel)), size: fi.Size(), modTime: fi.ModTime()})
		return nil
	})
	return jobs, err
}

func planDownload(ctx context.Context, v *vfs.FS, src, dst string, exact bool) ([]job, error) {
	e, err := v.Stat(ctx, src)
	if err != nil {
		return nil, err
	}
	if !e.IsDir {
		target := dst
		if !exact {
			target = filepath.Join(dst, e.Name)
		}
		return []job{{src: e.Path, dst: target, size: e.Size, modTime: e.ModTime}}, nil
	}
	if exact {
		return nil, errors.New("copyto needs a file as SRC; use copy for directories")
	}
	entries, err := v.List(ctx, src, true)
	if err != nil {
		return nil, err
	}
	var jobs []job
	for _, e := range entries {
		rel := strings.TrimPrefix(e.Path, strings.TrimSuffix(src, "/")+"/")
		jobs = append(jobs, job{src: e.Path, dst: filepath.Join(dst, filepath.FromSlash(rel)), size: e.Size, modTime: e.ModTime})
	}
	return jobs, nil
}

// unchanged reports whether the destination already has this file: same
// size and, where both sides know it, the same modification time.
func unchanged(ctx context.Context, v *vfs.FS, j job, upload, ignoreExisting bool) (bool, error) {
	var size int64
	var mt time.Time
	if upload {
		e, err := v.Stat(ctx, j.dst)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if e.IsDir {
			return false, fmt.Errorf("%s is a directory in the pool", j.dst)
		}
		size, mt = e.Size, e.ModTime
	} else {
		fi, err := os.Stat(j.dst)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		size, mt = fi.Size(), fi.ModTime()
	}
	if ignoreExisting {
		return true, nil
	}
	if size != j.size {
		return false, nil
	}
	return mt.IsZero() || j.modTime.IsZero() || mt.Equal(j.modTime), nil
}

func uploadOne(ctx context.Context, v *vfs.FS, j job) error {
	f, err := os.Open(j.src)
	if err != nil {
		return err
	}
	defer f.Close()
	t := st.Begin(j.dst, j.size)
	_, err = v.Put(ctx, j.dst, t.Reader(f), j.modTime)
	t.Done(err)
	return err
}

func downloadOne(ctx context.Context, v *vfs.FS, j job) error {
	f, m, err := v.Open(ctx, j.src)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(j.dst), 0o755); err != nil {
		return err
	}
	tmp := j.dst + ".mppart"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	t := st.Begin(j.src, m.Size)
	_, err = io.Copy(out, t.Reader(f))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		t.Done(err)
		return err
	}
	err = os.Rename(tmp, j.dst)
	if err == nil && !j.modTime.IsZero() {
		_ = os.Chtimes(j.dst, j.modTime, j.modTime)
	}
	t.Done(err)
	return err
}

// startProgress prints a live status line with -P; the returned func stops
// it (safe to call twice).
func startProgress() func() {
	if !g.progress {
		return func() {}
	}
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				fmt.Fprint(os.Stderr, "\r\033[K")
				return
			case <-t.C:
				s := st.Snapshot()
				line := fmt.Sprintf("Transferred: %s, %s/s, %d done, %d active", human(s.Bytes), human(int64(s.Speed)), s.Transfers, len(s.Transferring))
				for _, a := range s.Transferring[:min(2, len(s.Transferring))] {
					line += fmt.Sprintf(" | %s %d%%", path.Base(a.Name), a.Percentage)
				}
				fmt.Fprint(os.Stderr, "\r\033[K"+line)
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }) }
}

func addCmd() *cobra.Command {
	var infohash, tfile string
	cmd := &cobra.Command{
		Use:   "add <file> pool:path",
		Short: "Add one file, optionally recording the torrent it came from (lets bridges repair it from the swarm)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			var src *client.Source
			if infohash != "" {
				src = &client.Source{Infohash: strings.ToLower(infohash), File: tfile}
				if src.File == "" {
					src.File = filepath.Base(args[0])
				}
			}
			s, err := v.C.AddFile(cmd.Context(), args[0], vfs.Clean(args[1]), src)
			if err != nil {
				return err
			}
			fmt.Printf("added %s: %d segments, %d already in pool, %s uploaded for %s of content\n",
				vfs.Clean(args[1]), s.Segments, s.Deduped, human(s.Uploaded), human(s.PlainSize))
			return nil
		},
	}
	cmd.Flags().StringVar(&infohash, "torrent", "", "infohash of the torrent this file came from")
	cmd.Flags().StringVar(&tfile, "torrent-file", "", "path of this file inside the torrent (default: base name)")
	return cmd
}

func deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete pool:path",
		Short: "Delete every file you added at or under a path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			removed, notOwned, err := v.RemoveAll(cmd.Context(), args[0], g.dryRun)
			verb := "deleted"
			if g.dryRun {
				verb = "would delete"
			}
			for _, p := range removed {
				fmt.Printf("%s %s\n", verb, p)
			}
			if len(notOwned) > 0 {
				fmt.Fprintf(os.Stderr, "kept %d files added by other members\n", len(notOwned))
			}
			return err
		},
	}
}

func deletefileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deletefile pool:path",
		Short: "Delete one file you added",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			if g.dryRun {
				fmt.Println("would delete", vfs.Clean(args[0]))
				return nil
			}
			return v.Remove(cmd.Context(), args[0])
		},
	}
}
