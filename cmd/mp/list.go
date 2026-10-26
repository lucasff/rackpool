package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"mediapool/internal/vfs"
)

func poolArg(args []string) string {
	if len(args) == 0 {
		return "/"
	}
	return vfs.Clean(args[0])
}

func lsCommands() []*cobra.Command {
	var recurse bool
	list := func(use, short string, recursiveDefault bool, print func(w io.Writer, e vfs.Entry, base string)) *cobra.Command {
		cmd := &cobra.Command{
			Use:   use + " [pool:path]",
			Short: short,
			Args:  cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				v, err := openFS()
				if err != nil {
					return err
				}
				dir := poolArg(args)
				r := recursiveDefault || recurse
				entries, err := v.List(cmd.Context(), dir, r)
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
				for _, e := range entries {
					print(w, e, dir)
				}
				return w.Flush()
			},
		}
		if !recursiveDefault {
			cmd.Flags().BoolVarP(&recurse, "recursive", "R", false, "recurse into directories")
		}
		return cmd
	}
	rel := func(p, base string) string {
		return strings.TrimPrefix(strings.TrimPrefix(p, strings.TrimSuffix(base, "/")), "/")
	}
	ls := list("ls", "List files with sizes (recursive)", true, func(w io.Writer, e vfs.Entry, base string) {
		fmt.Fprintf(w, "%d\t %s\n", e.Size, rel(e.Path, base))
	})
	lsl := list("lsl", "List files with sizes and modification times (recursive)", true, func(w io.Writer, e vfs.Entry, base string) {
		fmt.Fprintf(w, "%d\t %s %s\n", e.Size, e.ModTime.Format("2006-01-02 15:04:05.000000000"), rel(e.Path, base))
	})
	lsd := list("lsd", "List directories", false, func(w io.Writer, e vfs.Entry, base string) {
		if e.IsDir {
			fmt.Fprintf(w, "%d\t %s %s\n", e.Size, e.ModTime.Format(time.DateTime), rel(e.Path, base))
		}
	})
	lsf := list("lsf", "List names, directories with a trailing /", false, func(w io.Writer, e vfs.Entry, base string) {
		suffix := ""
		if e.IsDir {
			suffix = "/"
		}
		fmt.Fprintln(w, rel(e.Path, base)+suffix)
	})

	var jsonRecurse bool
	lsjson := &cobra.Command{
		Use:   "lsjson [pool:path]",
		Short: "List as JSON",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			entries, err := v.List(cmd.Context(), poolArg(args), jsonRecurse)
			if err != nil {
				return err
			}
			if entries == nil {
				entries = []vfs.Entry{}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		},
	}
	lsjson.Flags().BoolVarP(&jsonRecurse, "recursive", "R", false, "recurse into directories")

	tree := &cobra.Command{
		Use:   "tree [pool:path]",
		Short: "Show the directory tree",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			dir := poolArg(args)
			entries, err := v.List(cmd.Context(), dir, true)
			if err != nil {
				return err
			}
			fmt.Println(dir)
			printed := map[string]bool{}
			files, dirs := 0, 0
			for _, e := range entries {
				parts := strings.Split(rel(e.Path, dir), "/")
				for i := range parts {
					key := strings.Join(parts[:i+1], "/")
					if printed[key] {
						continue
					}
					printed[key] = true
					label := parts[i]
					if i < len(parts)-1 {
						label += "/"
						dirs++
					} else {
						label = fmt.Sprintf("%s  (%s)", label, human(e.Size))
						files++
					}
					fmt.Println(strings.Repeat("    ", i) + "├── " + label)
				}
			}
			fmt.Printf("\n%d directories, %d files\n", dirs, files)
			return nil
		},
	}
	return []*cobra.Command{ls, lsl, lsd, lsf, lsjson, tree}
}

func sizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "size [pool:path]",
		Short: "Total size and number of files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			entries, err := v.List(cmd.Context(), poolArg(args), true)
			if err != nil {
				return err
			}
			var total int64
			for _, e := range entries {
				total += e.Size
			}
			fmt.Printf("Total objects: %d\nTotal size: %s (%d bytes)\n", len(entries), human(total), total)
			return nil
		},
	}
}

func catCmd() *cobra.Command {
	var offset, count, head, tail int64
	cmd := &cobra.Command{
		Use:   "cat pool:path",
		Short: "Write a file to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			f, m, err := v.Open(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			switch {
			case head > 0:
				count = head
			case tail > 0:
				offset, count = max(0, m.Size-tail), tail
			}
			if offset > 0 {
				if _, err := f.Seek(offset, io.SeekStart); err != nil {
					return err
				}
			}
			var r io.Reader = f
			if count > 0 {
				r = io.LimitReader(f, count)
			}
			_, err = io.Copy(os.Stdout, r)
			return err
		},
	}
	cmd.Flags().Int64Var(&offset, "offset", 0, "start at this byte")
	cmd.Flags().Int64Var(&count, "count", 0, "read this many bytes")
	cmd.Flags().Int64Var(&head, "head", 0, "only the first N bytes")
	cmd.Flags().Int64Var(&tail, "tail", 0, "only the last N bytes")
	return cmd
}

func aboutCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "about",
		Short: "Library and pool totals",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			a, _, err := v.About(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(a)
			}
			fmt.Printf("Files:      %d (%s)\nYours:      %d (%s)\nUnique:     %s (dedup %.1f×)\nSegments:   %d\nNodes:      %d online of %d (%d via relay)\nOffered:    %s\nStored:     %s (%.2f× the unique content)\nCatalog:    entry %d\n",
				a.Files, human(a.Bytes), a.MyFiles, human(a.MyBytes), human(a.Unique), a.Dedup, a.Segments, a.NodesUp, a.Nodes, a.Relayed,
				human(a.Offered), human(a.Used), a.Overhead, a.CatalogSeq)
			if a.Blocked != "" {
				fmt.Printf("WRITES BLOCKED: %s\n", a.Blocked)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Nodes and segments as the coordinator sees them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := openFS()
			if err != nil {
				return err
			}
			s, err := v.C.Status(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "catalog head %d", s.Head.Seq)
			if s.WriteBlocked != "" {
				fmt.Fprintf(tw, " (WRITES BLOCKED: %s)", s.WriteBlocked)
			}
			fmt.Fprintf(tw, "\n\nNODE\tOWNER\tONLINE\tREACH\tBRIDGE\tSHARDS\tUSED\tFREE\tUP\tDRAIN\tSTRIKES\tFAIL-P\n")
			for _, n := range s.Nodes {
				free, up := "?", "∞"
				if n.Capacity.Free >= 0 {
					free = human(n.Capacity.Free)
				}
				if n.Capacity.UploadBps > 0 {
					up = fmt.Sprintf("%.0fMbit", float64(n.Capacity.UploadBps)*8/1e6)
				}
				reach := n.Reach
				if reach == "" {
					reach = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%v\t%d\t%s\t%s\t%s\t%v\t%d\t%.3f\n", n.ID, n.Owner, n.Online, reach, n.Bridge, n.Shards,
					human(n.Capacity.Used), free, up, n.Capacity.Drain, n.Strikes, n.FailProb)
			}
			fmt.Fprintf(tw, "\nSEGMENT\tCLASS\tREFS\tONLINE/DURABLE/TARGET\tLOSS-P\tHEAT(reads/min)\tREPAIRING\n")
			for _, sg := range s.Segments {
				target := fmt.Sprint(sg.Target)
				if sg.Target == 0 {
					target = "auto"
				}
				fmt.Fprintf(tw, "%.12s\t%s\t%d\t%d/%d/%s\t%.1e\t%.1f\t%v\n", sg.ID, sg.Class, sg.Refs, sg.Online, sg.Durable, target, sg.LossProb, sg.HeatPerMin, sg.Repairing)
			}
			return tw.Flush()
		},
	}
}

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
