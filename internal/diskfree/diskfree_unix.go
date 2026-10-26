//go:build !windows

// Package diskfree reports free space on the filesystem holding a path.
package diskfree

import "golang.org/x/sys/unix"

// Free returns the bytes available to unprivileged users under path.
func Free(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
