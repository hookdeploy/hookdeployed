package tap

import (
	"fmt"
	"strings"
	"time"
)

func FormatList(endpoints []Endpoint, taps []Tap) string {
	var b strings.Builder
	if len(endpoints) == 0 {
		fmt.Fprintln(&b, "No endpoints in this organization.")
	} else {
		for i, ep := range endpoints {
			if i > 0 {
				fmt.Fprintln(&b)
			}
			fmt.Fprintf(&b, "%s\n", displayName(ep))
			fmt.Fprintf(&b, "  %s\n", ep.ID)
			if len(ep.Destinations) == 0 {
				fmt.Fprintln(&b, "  (no destinations)")
				continue
			}
			for _, d := range ep.Destinations {
				fmt.Fprintf(&b, "  %s (%s)\n", displayDestName(d), destKind(d))
				fmt.Fprintf(&b, "    %s\n", d.ID)
			}
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "RUNNING TAPS")
	if len(taps) == 0 {
		fmt.Fprintln(&b, "  (none)")
		return b.String()
	}
	for _, t := range taps {
		name, dest := resolveTapNames(endpoints, t)
		fmt.Fprintf(&b, "%s\n", t.ID)
		fmt.Fprintf(&b, "  %s / %s  %s  %s\n", name, dest, formatTarget(t), formatExpires(t.ExpiresAt))
	}
	return b.String()
}

func resolveTapNames(endpoints []Endpoint, t Tap) (slug, dest string) {
	dest = "(endpoint)"
	for _, ep := range endpoints {
		if ep.ID != t.EndpointID {
			continue
		}
		slug = displayName(ep)
		if t.DestinationID == nil || *t.DestinationID == "" {
			return slug, dest
		}
		for _, d := range ep.Destinations {
			if d.ID == *t.DestinationID {
				return slug, d.Name
			}
		}
		return slug, *t.DestinationID
	}
	if slug == "" {
		slug = t.EndpointID
	}
	if t.DestinationID != nil && *t.DestinationID != "" {
		dest = *t.DestinationID
	}
	return slug, dest
}

func displayName(ep Endpoint) string {
	if strings.TrimSpace(ep.Name) != "" {
		return ep.Name
	}
	if strings.TrimSpace(ep.Slug) != "" {
		return ep.Slug
	}
	return ep.ID
}

func displayDestName(d Destination) string {
	if strings.TrimSpace(d.Name) != "" {
		return d.Name
	}
	return d.ID
}

func destKind(d Destination) string {
	if d.DestinationType == "" {
		return "https"
	}
	return d.DestinationType
}

func formatTarget(t Tap) string {
	path := t.TargetPath
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("127.0.0.1:%d%s", t.TargetPort, path)
}

func FormatCreated(opts StartOpts, created Tap) string {
	target := formatTarget(created)
	if created.TargetPort == 0 {
		target = fmt.Sprintf("127.0.0.1:%d%s", opts.Port, opts.Path)
	}
	expires := formatExpires(created.ExpiresAt)
	if expires == "" {
		expires = "(server default, max 8h)"
	}
	dest := strings.TrimSpace(opts.DestinationID)
	if dest == "" {
		dest = "(endpoint)"
	}
	return fmt.Sprintf(
		"Tapping %s / %s → %s\nExpires %s\n",
		opts.EndpointID,
		dest,
		target,
		expires,
	)
}

func formatExpires(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC().Format("2006-01-02 15:04 UTC")
		}
	}
	return raw
}
