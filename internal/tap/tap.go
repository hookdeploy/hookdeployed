package tap

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

const (
	TargetsPath = "/v1/agents/tap-targets"
	CreatePath  = "/v1/agents/taps"
	ListPath    = "/v1/agents/taps/list"
	StopPath    = "/v1/agents/taps/stop"

	// NeedsTTY is the non-TTY refusal for the blocking create command.
	// Same discipline as switch and enroll: a script must not hold a tap
	// open with nobody watching.
	NeedsTTY = "not a TTY; agent tap blocks until Ctrl+C. Run it in a terminal."

	// ConnectHint is printed after a tap is created. The CLI cannot see
	// whether connect is running; deliveries are silent without it.
	ConnectHint = "Deliveries land only while `agent connect` is running on this machine."

	Usage = `usage: agent tap list
       agent tap <endpoint-slug> [<dest-name>] -port PORT -path PATH [-duration DUR]
       agent tap stop [id]`
)

type Endpoint struct {
	ID           string        `json:"id"`
	Slug         string        `json:"slug"`
	Name         string        `json:"name"`
	Destinations []Destination `json:"destinations"`
}

type Destination struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	DestinationType string `json:"destination_type"`
}

type Tap struct {
	ID               string  `json:"id"`
	OrganizationID   string  `json:"organization_id"`
	EndpointID       string  `json:"endpoint_id"`
	DestinationID    *string `json:"destination_id"`
	AgentID          string  `json:"agent_id"`
	CreatedByAgentID string  `json:"created_by_agent_id"`
	TargetPort       int     `json:"target_port"`
	TargetPath       string  `json:"target_path"`
	CreatedAt        string  `json:"created_at"`
	ExpiresAt        string  `json:"expires_at"`
	EndedAt          *string `json:"ended_at"`
}

type Config struct {
	Root      string
	EnrollURL string
	TTY       bool
	Stdout    io.Writer
	Client    *enroll.Client
	// Wait holds the blocking tap open. Tests replace it. Nil waits on ctx.
	Wait func(ctx context.Context) error
	// Stop overrides Client stop (tests). Nil uses the real call.
	Stop func(token, tapID string) error
}

func (c Config) client() *enroll.Client {
	if c.Client != nil {
		return c.Client
	}
	return enroll.NewClient(strings.TrimRight(c.EnrollURL, "/"))
}

func (c Config) out() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return io.Discard
}

type tokenMaterial struct {
	Token string
}

func loadToken(root string) (tokenMaterial, error) {
	orgDir, err := store.ResolveActiveDir(root)
	if err != nil {
		return tokenMaterial{}, store.ExplainResolve(root, err)
	}
	material, err := store.Load(orgDir)
	if err != nil {
		return tokenMaterial{}, err
	}
	token := strings.TrimSpace(material.RenewalToken)
	if token == "" {
		return tokenMaterial{}, fmt.Errorf("no renewal token — run `agent enroll`")
	}
	return tokenMaterial{Token: token}, nil
}

func wrapAPIError(err error) error {
	if err == nil {
		return nil
	}
	var api *enroll.APIError
	if !errors.As(err, &api) {
		return err
	}
	if api.Code == "ambiguous_destination" {
		return formatAmbiguous(api)
	}
	if api.Message != "" {
		return fmt.Errorf("%s", api.Message)
	}
	if api.Code != "" {
		return fmt.Errorf("%s", api.Code)
	}
	return err
}

func formatAmbiguous(api *enroll.APIError) error {
	var b strings.Builder
	msg := api.Message
	if msg == "" {
		msg = "Multiple destinations share that name."
	}
	fmt.Fprintln(&b, msg)
	for _, d := range api.Destinations {
		fmt.Fprintf(&b, "  %s  %s  %s\n", d.ID, d.Name, d.DestinationType)
	}
	fmt.Fprint(&b, "The CLI creates taps by destination name. Rename one destination so the name is unique, then retry.")
	return fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
}

func fetchTargets(c *enroll.Client, token string) ([]Endpoint, error) {
	var out struct {
		Endpoints []Endpoint `json:"endpoints"`
	}
	if err := c.Post(TargetsPath, map[string]string{"renewal_token": token}, &out); err != nil {
		return nil, wrapAPIError(err)
	}
	if out.Endpoints == nil {
		return []Endpoint{}, nil
	}
	return out.Endpoints, nil
}

func fetchTaps(c *enroll.Client, token string) ([]Tap, error) {
	var out struct {
		Taps []Tap `json:"taps"`
	}
	if err := c.Post(ListPath, map[string]string{"renewal_token": token}, &out); err != nil {
		return nil, wrapAPIError(err)
	}
	if out.Taps == nil {
		return []Tap{}, nil
	}
	return out.Taps, nil
}

func createTap(c *enroll.Client, token, slug, destName string, port int, path string, durationSeconds *int) (Tap, error) {
	body := map[string]any{
		"renewal_token": token,
		"endpoint_slug": slug,
		"target_port":   port,
		"target_path":   path,
	}
	if destName != "" {
		body["destination_name"] = destName
	}
	if durationSeconds != nil {
		body["duration_seconds"] = *durationSeconds
	}
	var out struct {
		Tap Tap `json:"tap"`
	}
	if err := c.Post(CreatePath, body, &out); err != nil {
		return Tap{}, wrapAPIError(err)
	}
	return out.Tap, nil
}

func stopTap(c *enroll.Client, token, tapID string) (Tap, error) {
	var out struct {
		Tap Tap `json:"tap"`
	}
	if err := c.Post(StopPath, map[string]any{
		"renewal_token": token,
		"tap_id":        tapID,
	}, &out); err != nil {
		return Tap{}, wrapAPIError(err)
	}
	return out.Tap, nil
}

func List(cfg Config) error {
	tok, err := loadToken(cfg.Root)
	if err != nil {
		return err
	}
	client := cfg.client()
	endpoints, err := fetchTargets(client, tok.Token)
	if err != nil {
		return err
	}
	taps, err := fetchTaps(client, tok.Token)
	if err != nil {
		return err
	}
	fmt.Fprint(cfg.out(), FormatList(endpoints, taps))
	return nil
}

func Stop(cfg Config, tapID string) error {
	tok, err := loadToken(cfg.Root)
	if err != nil {
		return err
	}
	client := cfg.client()
	id := strings.TrimSpace(tapID)
	if id == "" {
		taps, err := fetchTaps(client, tok.Token)
		if err != nil {
			return err
		}
		switch len(taps) {
		case 0:
			return fmt.Errorf("No running taps.")
		case 1:
			id = taps[0].ID
		default:
			var b strings.Builder
			fmt.Fprintln(&b, "multiple taps are running; specify one: agent tap stop <id>")
			for _, t := range taps {
				fmt.Fprintf(&b, "  %s\n", t.ID)
			}
			return fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
		}
	}
	if _, err := stopTap(client, tok.Token, id); err != nil {
		return err
	}
	fmt.Fprintf(cfg.out(), "Stopped tap %s.\n", id)
	return nil
}

type StartOpts struct {
	Slug     string
	DestName string
	Port     int
	Path     string
	Duration time.Duration
}

func Start(ctx context.Context, cfg Config, opts StartOpts) error {
	if strings.TrimSpace(opts.Slug) == "" {
		return fmt.Errorf("%s", Usage)
	}
	if opts.Port == 0 {
		return fmt.Errorf("-port is required")
	}
	if strings.TrimSpace(opts.Path) == "" {
		return fmt.Errorf("-path is required")
	}
	if !strings.HasPrefix(opts.Path, "/") {
		return fmt.Errorf("Path must start with /.")
	}
	if !cfg.TTY {
		return fmt.Errorf("%s", NeedsTTY)
	}

	tok, err := loadToken(cfg.Root)
	if err != nil {
		return err
	}
	client := cfg.client()

	var durationSeconds *int
	if opts.Duration > 0 {
		sec := int(opts.Duration / time.Second)
		durationSeconds = &sec
	}

	created, err := createTap(client, tok.Token, opts.Slug, opts.DestName, opts.Port, opts.Path, durationSeconds)
	if err != nil {
		return err
	}

	fmt.Fprint(cfg.out(), FormatCreated(opts, created))
	if opts.DestName == "" {
		fmt.Fprint(cfg.out(), "This is an endpoint tap. Destination taps are what currently deliver; pass a destination name to receive production HTTPS traffic.\n")
	}
	fmt.Fprintln(cfg.out(), ConnectHint)
	fmt.Fprintln(cfg.out(), "Ctrl+C stops the tap.")

	wait := cfg.Wait
	if wait == nil {
		wait = func(waitCtx context.Context) error {
			<-waitCtx.Done()
			return nil
		}
	}
	_ = wait(ctx)

	stopFn := cfg.Stop
	if stopFn == nil {
		stopFn = func(token, id string) error {
			_, err := stopTap(client, token, id)
			return err
		}
	}
	if err := stopFn(tok.Token, created.ID); err != nil {
		return failedStopError(created, err)
	}
	fmt.Fprintf(cfg.out(), "Stopped tap %s.\n", created.ID)
	return nil
}

func failedStopError(created Tap, err error) error {
	expires := created.ExpiresAt
	if formatted := formatExpires(created.ExpiresAt); formatted != "" {
		expires = formatted
	}
	msg := err.Error()
	var api *enroll.APIError
	if errors.As(err, &api) && api.Message != "" {
		msg = api.Message
	}
	return fmt.Errorf("could not stop tap %s: %s\nThe tap is still live and will linger until it expires (%s) or this agent disconnects.", created.ID, msg, expires)
}

func ParseStartFlags(fs *flag.FlagSet, args []string) (StartOpts, error) {
	port := fs.Int("port", 0, "local port that receives the tapped delivery")
	path := fs.String("path", "", "local path (must start with /)")
	duration := fs.Duration("duration", 0, "how long the tap stays live (server clamps at 8h)")
	positionals, err := assignFlagsAnywhere(fs, args)
	if err != nil {
		return StartOpts{}, err
	}
	opts := StartOpts{
		Port:     *port,
		Path:     *path,
		Duration: *duration,
	}
	if len(positionals) >= 1 {
		opts.Slug = positionals[0]
	}
	if len(positionals) >= 2 {
		opts.DestName = strings.Join(positionals[1:], " ")
	}
	return opts, nil
}

func assignFlagsAnywhere(fs *flag.FlagSet, args []string) (positionals []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(positionals, args[i+1:]...), nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if name == "" {
			positionals = append(positionals, a)
			continue
		}
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			if err := fs.Set(name[:eq], name[eq+1:]); err != nil {
				return nil, err
			}
			continue
		}
		if fs.Lookup(name) == nil {
			return nil, fmt.Errorf("flag provided but not defined: -%s", name)
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("flag needs an argument: -%s", name)
		}
		i++
		if err := fs.Set(name, args[i]); err != nil {
			return nil, err
		}
	}
	return positionals, nil
}
