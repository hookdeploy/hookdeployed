package enroll

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

const (
	UnenrollNeedsYes = "not a TTY; pass --yes to unenroll without a prompt"

	UnenrollConfirmPrefix = "This will delete local credentials for"
	UnenrollConfirmSuffix = "and revoke the agent on the server.\nThis cannot be undone without re-enrolling.\nContinue? [y/N] "
)

type UnenrollConfig struct {
	Root      string
	EnrollURL string
	LocalOnly bool
	Yes       bool
	Query     string
	// Revoke overrides Client.SelfRevoke (tests). Nil uses the real call.
	Revoke func(enrollURL, token string) error
}

func Unenroll(cfg UnenrollConfig, in io.Reader, out io.Writer, tty bool) error {
	orgs, err := store.List(cfg.Root)
	if err != nil {
		return err
	}

	target, err := resolveUnenrollTarget(cfg.Root, orgs, cfg.Query)
	if err != nil {
		return err
	}
	label := target.Name
	if strings.TrimSpace(label) == "" {
		label = target.ID
	}

	if !cfg.Yes {
		if !tty {
			return fmt.Errorf("%s", UnenrollNeedsYes)
		}
		fmt.Fprintf(out, "%s %s %s", UnenrollConfirmPrefix, label, UnenrollConfirmSuffix)
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil {
			return fmt.Errorf("unenroll: read confirmation: %w", err)
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "y" && answer != "yes" {
			return fmt.Errorf("unenroll cancelled")
		}
	}

	orgID := filepath.Base(target.Dir)
	others := 0
	for _, o := range orgs {
		if filepath.Base(o.Dir) != orgID && o.ID != orgID {
			others++
		}
	}

	if !cfg.LocalOnly {
		material, err := store.Load(target.Dir)
		if err != nil {
			return err
		}
		token := strings.TrimSpace(material.RenewalToken)
		if token == "" {
			return fmt.Errorf("no renewal token on disk — cannot revoke on the server. Pass --local-only to delete credentials and leave the dashboard record")
		}
		revoke := cfg.Revoke
		if revoke == nil {
			revoke = func(enrollURL, tok string) error {
				return NewClient(enrollURL).SelfRevoke(tok)
			}
		}
		if err := revoke(cfg.EnrollURL, token); err != nil {
			return fmt.Errorf("could not revoke the agent on the server: %w\nLocal credentials were kept. Re-run when online, or pass --local-only to delete them and leave the dashboard record", err)
		}
	}

	if err := store.RemoveOrg(cfg.Root, orgID); err != nil {
		return err
	}

	if cfg.LocalOnly {
		fmt.Fprintf(out, "removed local credentials for %s. The agent record was not revoked (--local-only).\n", label)
		if others > 0 {
			fmt.Fprintf(out, "Other organizations are still enrolled. Run `agent switch` to pick one.\n")
		}
		return nil
	}
	if others > 0 {
		fmt.Fprintf(out, "unenrolled %s. Other organizations are still enrolled. Run `agent switch` to pick one.\n", label)
		return nil
	}
	fmt.Fprintf(out, "unenrolled %s. Local credentials were removed. Run `agent enroll` to enroll again.\n", label)
	return nil
}

func resolveUnenrollTarget(root string, orgs []store.Enrollment, query string) (store.Enrollment, error) {
	if strings.TrimSpace(query) != "" {
		if len(orgs) == 0 {
			return store.Enrollment{}, store.ExplainResolve(root, store.ErrNotEnrolled)
		}
		return store.Match(orgs, query)
	}
	dir, err := store.ResolveActiveDir(root)
	if err != nil {
		return store.Enrollment{}, store.ExplainResolve(root, err)
	}
	for _, o := range orgs {
		if o.Dir == dir || filepath.Base(o.Dir) == filepath.Base(dir) {
			return o, nil
		}
	}
	return store.Enrollment{}, store.ExplainResolve(root, store.ErrNotEnrolled)
}
