package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"mediapool/deploy"
	"mediapool/internal/auth"
	"mediapool/internal/catalog"
	"mediapool/internal/invite"
	"mediapool/internal/limits"
	"mediapool/internal/transfer"
)

// identity loads the configured member's key for admin calls.
func identity() (*auth.Identity, error) {
	if g.member == "" {
		return nil, errors.New("--member (MP_MEMBER) is not set")
	}
	k, err := auth.LoadOrCreateKey(g.key)
	if err != nil {
		return nil, err
	}
	return auth.NewIdentity(k), nil
}

func writeEnv(path string, kv [][2]string) error {
	var b strings.Builder
	b.WriteString("# mediapool settings. Keep this file private.\n")
	for _, p := range kv {
		fmt.Fprintf(&b, "%s=%s\n", p[0], p[1])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func poolCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pool", Short: "Create a pool"}
	var dir, name, coordURL string
	var tunnel bool
	var segSize string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new pool: keys, secret, pool.json and a Docker Compose file for the founder",
		Long: "Creates everything the founder needs in --dir: the coordinator key, the pool secret, your member\n" +
			"and node keys, pool.json listing you as the first (admin) member, mediapool.env and a\n" +
			"docker-compose.yml that runs the coordinator and your storage node. Then invite people with\n" +
			"`mp invite create`.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if coordURL == "" {
				return errors.New("--coord-url is required: the address members will reach your coordinator at, e.g. http://my-name.duckdns.org:7000")
			}
			if _, err := os.Stat(filepath.Join(dir, "pool.json")); err == nil {
				return fmt.Errorf("%s already holds a pool", dir)
			}
			for _, d := range []string{"coord", "node", "member"} {
				if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
					return err
				}
			}
			coordKey, err := auth.LoadOrCreateKey(filepath.Join(dir, "coord", "coord.key"))
			if err != nil {
				return err
			}
			memberKey, err := auth.LoadOrCreateKey(filepath.Join(dir, "member", "member.key"))
			if err != nil {
				return err
			}
			nodeKey, err := auth.LoadOrCreateKey(filepath.Join(dir, "node", "node.key"))
			if err != nil {
				return err
			}
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return err
			}
			nodeID := name + "-node"
			pool := auth.Pool{
				Coordinator: auth.PubHex(coordKey),
				Members:     []auth.Member{{Name: name, Key: auth.PubHex(memberKey), Admin: true}},
				Nodes:       []auth.NodeEntry{{ID: nodeID, Key: auth.PubHex(nodeKey), Owner: name}},
			}
			b, _ := json.MarshalIndent(&pool, "", "  ")
			if err := os.WriteFile(filepath.Join(dir, "pool.json"), append(b, '\n'), 0o644); err != nil {
				return err
			}
			secretStr := base64.RawURLEncoding.EncodeToString(secret)
			if err := writeEnv(filepath.Join(dir, "mediapool.env"), [][2]string{
				{"MEDIAPOOL_SECRET", secretStr}, {"MP_COORD", coordURL}, {"MP_POOL", filepath.Join(dir, "pool.json")},
				{"MP_MEMBER", name}, {"MP_KEY", filepath.Join(dir, "member", "member.key")},
			}); err != nil {
				return err
			}
			u, err := url.Parse(coordURL)
			if err != nil || u.Host == "" {
				return fmt.Errorf("--coord-url %q isn't a URL", coordURL)
			}
			compose, reach := deploy.Founder, "Forward TCP 7000 and 7100 to this machine (or use --tunnel)"
			rcPass := make([]byte, 12)
			if _, err := rand.Read(rcPass); err != nil {
				return err
			}
			var sb limits.Bytes
			if err := sb.Set(segSize); err != nil {
				return fmt.Errorf("--segment-size: %w", err)
			}
			if err := (catalog.PoolConfig{SegmentSize: int(sb), K: 10, MaxN: 40}).Validate(); err != nil {
				return fmt.Errorf("--segment-size: %w", err)
			}
			envVars := [][2]string{{"NODE_ID", nodeID}, {"POOL_URL", coordURL}, {"RC_PASS", base64.RawURLEncoding.EncodeToString(rcPass)}, {"SEGMENT_SIZE", segSize}}
			if tunnel {
				if u.Scheme != "https" {
					return errors.New("with --tunnel, --coord-url is your tunnel's public hostname: https://pool.example.com")
				}
				compose, reach = deploy.FounderTunnel, "Create a Cloudflare Tunnel routing "+u.Host+" → http://coord:7000 and put its token in .env"
				envVars = append(envVars, [2]string{"POOL_HOSTNAME", u.Host}, [2]string{"TUNNEL_TOKEN", ""}, [2]string{"RELAY_LIMIT", "0"})
			}
			if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
				return err
			}
			if err := writeEnv(filepath.Join(dir, ".env"), envVars); err != nil {
				return err
			}
			fmt.Printf(`Created pool in %s

  pool.json            public keys: coordinator, you (%s, admin), your node (%s)
  mediapool.env        your settings, including the pool secret: keep it private
  coord/ node/ member/ private keys
  docker-compose.yml   coordinator + your storage node (.env holds its settings)

Next:
  1. %s.
  2. cd %s && docker compose up -d
     (adjust MP_QUOTA / MP_UPLOAD_LIMIT in docker-compose.yml first)
  3. Invite people:  set -a; . %s/mediapool.env; set +a
                     mp invite create --name bob
`, dir, name, nodeID, reach, dir, dir)
			return nil
		},
	}
	initCmd.Flags().StringVar(&dir, "dir", "mediapool", "directory to create the pool in")
	initCmd.Flags().StringVar(&name, "name", "", "your member name")
	initCmd.Flags().StringVar(&coordURL, "coord-url", "", "public URL of your coordinator, e.g. http://you.duckdns.org:7000, or https://pool.example.com with --tunnel")
	initCmd.Flags().StringVar(&segSize, "segment-size", "16Mi", "plaintext bytes per segment, fixed for the pool's lifetime: smaller starts playback and seeks faster, larger means fewer files and requests")
	initCmd.Flags().BoolVar(&tunnel, "tunnel", false, "expose the coordinator through a Cloudflare Tunnel: no open ports, your IP hidden from members")
	_ = initCmd.MarkFlagRequired("name")
	cmd.AddCommand(initCmd)
	return cmd
}

func inviteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "invite", Short: "Invite people to the pool (admins)"}
	var name string
	var admin bool
	var expires time.Duration
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a one-time invite and print it",
		Long:  "Prints an invite string to send to the new member. It holds the pool secret, so send it\nprivately. It works once and expires.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := identity()
			if err != nil {
				return err
			}
			secret := os.Getenv("MEDIAPOOL_SECRET")
			if secret == "" {
				return errors.New("MEDIAPOOL_SECRET is not set")
			}
			pool, err := auth.LoadPool(g.pool)
			if err != nil {
				return err
			}
			inv, err := invite.New(g.coord, pool.Coordinator, []byte(secret), name, admin)
			if err != nil {
				return err
			}
			req := catalog.InviteCreate{CodeHash: invite.Hash(inv.Code), Name: name, Admin: admin, ExpiresMs: time.Now().Add(expires).UnixMilli()}
			if err := transfer.PostJSON(cmd.Context(), http.DefaultClient, id, g.coord+"/v1/invites", req, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Invite for %q, valid for %v. Send it privately:\n\n", name, expires)
			fmt.Println(inv.String())
			fmt.Fprintf(os.Stderr, "\nThey join a storage node with MP_INVITE=<invite> in docker-compose.node.yml,\nor just the CLI with: mp join <invite>\n")
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "suggested member name for them")
	create.Flags().BoolVar(&admin, "admin", false, "let them invite and remove members too")
	create.Flags().DurationVar(&expires, "expires", 7*24*time.Hour, "how long the invite stays valid")
	cmd.AddCommand(create)
	return cmd
}

func joinCmd() *cobra.Command {
	var dir, name string
	cmd := &cobra.Command{
		Use:   "join <invite>",
		Short: "Join a pool as a member (CLI only; to contribute storage, run a node with MP_INVITE)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, err := invite.Parse(args[0])
			if err != nil {
				return err
			}
			if name == "" {
				name = inv.Name
			}
			if name == "" {
				return errors.New("--name is required (the invite doesn't suggest one)")
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			key, err := auth.LoadOrCreateKey(filepath.Join(dir, "member.key"))
			if err != nil {
				return err
			}
			if err := invite.Redeem(cmd.Context(), http.DefaultClient, inv, name, key, "", nil); err != nil {
				return err
			}
			if err := writeBootstrap(dir, inv); err != nil {
				return err
			}
			if err := writeEnv(filepath.Join(dir, "mediapool.env"), [][2]string{
				{"MEDIAPOOL_SECRET", string(inv.Secret)}, {"MP_COORD", inv.Coord}, {"MP_POOL", filepath.Join(dir, "pool.json")},
				{"MP_MEMBER", name}, {"MP_KEY", filepath.Join(dir, "member.key")},
			}); err != nil {
				return err
			}
			fmt.Printf("Joined as %s. Settings are in %s/mediapool.env:\n\n  set -a; . %s/mediapool.env; set +a\n  mp lsd pool:/\n", name, dir, dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "mediapool", "where to keep your key and settings")
	cmd.Flags().StringVar(&name, "name", "", "your member name (default: the one in the invite)")
	return cmd
}

func writeBootstrap(dir string, inv invite.Invite) error {
	b, _ := json.MarshalIndent(inv.Pool(), "", "  ")
	return os.WriteFile(filepath.Join(dir, "pool.json"), append(b, '\n'), 0o644)
}

func membersCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "member", Short: "List and remove members"}
	list := &cobra.Command{
		Use: "list", Short: "List members and their nodes", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := identity()
			if err != nil {
				return err
			}
			var out struct {
				Members []auth.Member    `json:"members"`
				Nodes   []auth.NodeEntry `json:"nodes"`
			}
			if err := transfer.GetJSON(cmd.Context(), http.DefaultClient, id, g.coord+"/v1/members", &out); err != nil {
				return err
			}
			seen := map[string]bool{}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "MEMBER\tADMIN\tNODES")
			for _, m := range out.Members {
				if seen[m.Name] {
					continue
				}
				seen[m.Name] = true
				var nodes []string
				for _, n := range out.Nodes {
					if n.Owner == m.Name && !seen["n/"+n.ID] {
						seen["n/"+n.ID] = true
						label := n.ID
						if n.Bridge {
							label += " (bridge)"
						}
						nodes = append(nodes, label)
					}
				}
				fmt.Fprintf(tw, "%s\t%v\t%s\n", m.Name, m.Admin, strings.Join(nodes, ", "))
			}
			return tw.Flush()
		},
	}
	remove := &cobra.Command{
		Use: "remove <name>", Short: "Remove a member and their nodes (admins)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := identity()
			if err != nil {
				return err
			}
			return transfer.PostJSON(cmd.Context(), http.DefaultClient, id, g.coord+"/v1/members/remove", catalog.MemberRemove{Name: args[0]}, nil)
		},
	}
	cmd.AddCommand(list, remove)
	return cmd
}

func nodesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "Register, remove and grant roles to storage nodes"}
	add := &cobra.Command{
		Use: "add <node-id> <node-key-file>", Short: "Register another node you run (key from mp-node -print-pubkey's key file)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := identity()
			if err != nil {
				return err
			}
			nk, err := auth.LoadOrCreateKey(args[1])
			if err != nil {
				return err
			}
			pub := auth.PubHex(nk)
			req := invite.NodeAddRequest{ID: args[0], Key: pub, Sig: auth.NewIdentity(nk).SignRaw(invite.NodeAddMessage(args[0], g.member, pub))}
			return transfer.PostJSON(cmd.Context(), http.DefaultClient, id, g.coord+"/v1/nodes", req, nil)
		},
	}
	remove := &cobra.Command{
		Use: "remove <node-id>", Short: "Remove a node (its owner or an admin); drain it first", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := identity()
			if err != nil {
				return err
			}
			return transfer.PostJSON(cmd.Context(), http.DefaultClient, id, g.coord+"/v1/nodes/remove", catalog.NodeRemove{ID: args[0]}, nil)
		},
	}
	bridge := &cobra.Command{
		Use: "bridge <node-id> <true|false>", Short: "Grant or revoke the bridge role (admins)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := identity()
			if err != nil {
				return err
			}
			return transfer.PostJSON(cmd.Context(), http.DefaultClient, id, g.coord+"/v1/nodes/bridge", catalog.NodeBridge{ID: args[0], Bridge: args[1] == "true"}, nil)
		},
	}
	cmd.AddCommand(add, remove, bridge)
	return cmd
}
