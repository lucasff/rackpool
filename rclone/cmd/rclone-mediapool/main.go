// rclone-mediapool is rclone with every standard backend and command, plus
// the mediapool backend.
package main

import (
	_ "github.com/rclone/rclone/backend/all"
	"github.com/rclone/rclone/cmd"
	_ "github.com/rclone/rclone/cmd/all"
	_ "github.com/rclone/rclone/lib/plugin"

	_ "mediapool/rclone/backend/mediapool"
)

func main() {
	cmd.Main()
}
