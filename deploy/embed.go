// Package deploy holds the Docker Compose files, embedded so `mp pool init`
// writes the same files that are documented here.
package deploy

import _ "embed"

//go:embed docker-compose.founder.yml
var Founder string

//go:embed docker-compose.founder-tunnel.yml
var FounderTunnel string
