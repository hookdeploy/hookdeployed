package tap

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	slugWidth = 24
	destWidth = 48
	idWidth   = 36
)

func FormatList(endpoints []Endpoint, taps []Tap) string {
	var b strings.Builder
	if len(endpoints) == 0 {
		fmt.Fprintln(&b, "No endpoints in this organization.")
	} else {
		fmt.Fprintln(&b, "ENDPOINT                  DESTINATIONS")
		for _, ep := range endpoints {
			slug := trunc(displaySlug(ep), slugWidth)
			fmt.Fprintf(&b, "%-*s  %s\n", slugWidth, slug, formatDestinations(ep.Destinations))
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "RUNNING TAPS")
	if len(taps) == 0 {
		fmt.Fprintln(&b, "  (none)")
		return b.String()
	}
	fmt.Fprintln(&b, "ID                                    ENDPOINT                  DEST            TARGET                           EXPIRES")
	for _, t := range taps {
		slug, dest := resolveTapNames(endpoints, t)
		fmt.Fprintf(&b, "%-*s  %-*s  %-14s  %-32s  %s\n",
			idWidth, trunc(t.ID, idWidth),
			slugWidth, trunc(slug, slugWidth),
			trunc(dest, 14),
			trunc(formatTarget(t), 32),
			formatExpires(t.ExpiresAt),
		)
	}
	return b.String()
}

func resolveTapNames(endpoints []Endpoint, t Tap) (slug, dest string) {
	dest = "(endpoint)"
	for _, ep := range endpoints {
		if ep.ID != t.EndpointID {
			continue
		}
		slug = displaySlug(ep)
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

func displaySlug(ep Endpoint) string {
	if strings.TrimSpace(ep.Slug) != "" {
		return ep.Slug
	}
	return ep.ID
}

func formatDestinations(dests []Destination) string {
	if len(dests) == 0 {
		return "(no destinations)"
	}
	parts := make([]string, 0, len(dests))
	for _, d := range dests {
		name := d.Name
		if strings.TrimSpace(name) == "" {
			name = d.ID
		}
		kind := d.DestinationType
		if kind == "" {
			kind = "https"
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", name, kind))
	}
	return trunc(strings.Join(parts, "  "), destWidth)
}

func formatTarget(t Tap) string {
	path := t.TargetPath
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("127.0.0.1:%d%s", t.TargetPort, path)
}

func FormatCreated(opts StartOpts, created Tap) string {
	dest := opts.DestName
	if dest == "" {
		dest = "(endpoint)"
	}
	target := formatTarget(created)
	if created.TargetPort == 0 {
		target = fmt.Sprintf("127.0.0.1:%d%s", opts.Port, opts.Path)
	}
	expires := formatExpires(created.ExpiresAt)
	if expires == "" {
		expires = "(server default, max 8h)"
	}
	return fmt.Sprintf("Tapping %s / %s → %s\nExpires %s\n", opts.Slug, dest, target, expires)
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

func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}
