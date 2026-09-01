package store

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ActiveFile     = "active"
	MigratingFile  = ".migrating"
	SystemInfoFile = "system-info.json"
)

// ErrNotEnrolled means the store has no loadable org directories.
var ErrNotEnrolled = errors.New("no enrolled organization")

// ErrNoActive means orgs are on disk but none is selected (active
// missing or stale). The user should `agent switch`, not re-enroll.
var ErrNoActive = errors.New("no organization selected")

// Enrollment is one per-org directory under the store root.
type Enrollment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Slug    string `json:"slug"`
	AgentID string `json:"agent_id"`
	Dir     string `json:"-"`
	Active  bool   `json:"active"`
}

func OrgDir(root, orgID string) string {
	return filepath.Join(root, orgID)
}

func ActivePath(root string) string {
	return filepath.Join(root, ActiveFile)
}

func migratingPath(root string) string {
	return filepath.Join(root, MigratingFile)
}

func HasMigrating(root string) bool {
	_, err := os.Stat(migratingPath(root))
	return err == nil
}

func IsFlatStore(root string) bool {
	_, err := os.Stat(filepath.Join(root, "client.key"))
	return err == nil
}

// LooksEnrolled reports a usable active org. A half-migrated store
// (.migrating present) is never enrolled, even if files already sit
// under <org_id>/. Does not repair the layout.
func LooksEnrolled(root string) bool {
	if HasMigrating(root) {
		return false
	}
	id, err := ReadActive(root)
	if err != nil || id == "" {
		return false
	}
	_, err = Load(OrgDir(root, id))
	return err == nil
}

func ReadActive(root string) (string, error) {
	raw, err := os.ReadFile(ActivePath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func WriteActive(root, orgID string) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return fmt.Errorf("active org id is empty")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return os.WriteFile(ActivePath(root), []byte(orgID+"\n"), 0o644)
}

func ClearActive(root string) error {
	err := os.Remove(ActivePath(root))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// EnsureLayout migrates a flat store into <org_id>/ and writes active.
// Already-migrated stores are a no-op. A missing root is a no-op.
func EnsureLayout(root string) error {
	if HasMigrating(root) || IsFlatStore(root) {
		return migrateFlat(root)
	}
	return nil
}

func migrateFlat(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(migratingPath(root), []byte("1\n"), 0o644); err != nil {
		return err
	}

	orgID, err := discoverMigrationOrgID(root)
	if err != nil {
		return err
	}
	dest := OrgDir(root, orgID)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}

	// client.key first: the root immediately stops looking enrolled.
	if err := moveIfExists(filepath.Join(root, "client.key"), filepath.Join(dest, "client.key")); err != nil {
		return err
	}
	for _, name := range []string{"client.crt", "renewal.token", "ca.crt", OrgMetaFile, SystemInfoFile} {
		if err := moveIfExists(filepath.Join(root, name), filepath.Join(dest, name)); err != nil {
			return err
		}
	}
	legacy := filepath.Join(filepath.Dir(root), SystemInfoFile)
	if err := moveIfExists(legacy, filepath.Join(dest, SystemInfoFile)); err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(dest, OrgMetaFile)); os.IsNotExist(err) {
		if err := WriteOrgMeta(dest, OrgMeta{ID: orgID}); err != nil {
			return err
		}
	}

	if err := WriteActive(root, orgID); err != nil {
		return err
	}
	return os.Remove(migratingPath(root))
}

func discoverMigrationOrgID(root string) (string, error) {
	if id, err := orgIDFromCertFile(filepath.Join(root, "client.crt")); err == nil && id != "" {
		return id, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("migrate store: cannot read org id: %w", err)
	}
	var found string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		id, idErr := orgIDFromCertFile(filepath.Join(root, e.Name(), "client.crt"))
		if idErr != nil || id == "" {
			continue
		}
		if found != "" && found != id {
			return "", fmt.Errorf("migrate store: interrupted and ambiguous org directories")
		}
		found = id
	}
	if found == "" {
		return "", fmt.Errorf("migrate store: client cert has no OU")
	}
	return found, nil
}

func orgIDFromCertFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return OrgIDFromCertPEM(raw)
}

// OrgIDFromCertPEM reads the leaf OU (organization id).
func OrgIDFromCertPEM(pemBytes []byte) (string, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		if len(cert.Subject.OrganizationalUnit) == 0 {
			return "", fmt.Errorf("client cert has no OU")
		}
		id := strings.TrimSpace(cert.Subject.OrganizationalUnit[0])
		if id == "" {
			return "", fmt.Errorf("client cert has no OU")
		}
		return id, nil
	}
	return "", fmt.Errorf("client cert has no OU")
}

func moveIfExists(src, dest string) error {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Rename(src, dest); err == nil {
		return nil
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, raw, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Remove(src)
}

// ResolveActiveDir runs EnsureLayout, then returns the active org directory.
// A stale active pointer (directory gone) is cleared. Missing or stale
// active with other orgs still enrolled returns ErrNoActive; zero orgs
// returns ErrNotEnrolled.
func ResolveActiveDir(root string) (string, error) {
	if err := EnsureLayout(root); err != nil {
		return "", err
	}
	if HasMigrating(root) {
		return "", noActiveOrEmpty(root)
	}
	id, err := ReadActive(root)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", noActiveOrEmpty(root)
	}
	dir := OrgDir(root, id)
	if _, err := Load(dir); err != nil {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			_ = ClearActive(root)
		}
		return "", noActiveOrEmpty(root)
	}
	return dir, nil
}

func noActiveOrEmpty(root string) error {
	orgs, err := List(root)
	if err != nil {
		return err
	}
	if len(orgs) == 0 {
		return ErrNotEnrolled
	}
	return ErrNoActive
}

// ExplainResolve turns ResolveActiveDir errors into the user-facing line.
func ExplainResolve(root string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNoActive) {
		orgs, listErr := List(root)
		msg := "no organization selected. Run `agent switch` to pick one."
		if listErr == nil && len(orgs) > 0 {
			return fmt.Errorf("%s\n%s", msg, strings.TrimRight(FormatList(orgs), "\n"))
		}
		return fmt.Errorf("%s", msg)
	}
	if errors.Is(err, ErrNotEnrolled) {
		return fmt.Errorf("no enrolled cert in %s — run `agent enroll` first", root)
	}
	return err
}

func ListOrgDirs(root string) ([]string, error) {
	orgs, err := List(root)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(orgs))
	for _, o := range orgs {
		dirs = append(dirs, o.Dir)
	}
	return dirs, nil
}

func List(root string) ([]Enrollment, error) {
	if err := EnsureLayout(root); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	active, _ := ReadActive(root)
	var out []Enrollment
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := OrgDir(root, e.Name())
		material, err := Load(dir)
		if err != nil {
			continue
		}
		meta, _ := LoadOrgMeta(dir)
		id := e.Name()
		if meta.ID != "" {
			id = meta.ID
		}
		agentID := ""
		if material.ClientCert != nil {
			agentID = material.ClientCert.Subject.CommonName
		}
		out = append(out, Enrollment{
			ID:      id,
			Name:    meta.Name,
			Slug:    meta.Slug,
			AgentID: agentID,
			Dir:     dir,
			Active:  active == e.Name() || active == id,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ClearOrgDir deletes enrollment files key-first, then org.json and
// system-info.json. Missing names are ignored.
func ClearOrgDir(dir string) error {
	var first error
	for _, name := range EnrollmentFiles {
		err := os.Remove(filepath.Join(dir, name))
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	for _, name := range []string{OrgMetaFile, SystemInfoFile} {
		err := os.Remove(filepath.Join(dir, name))
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

// RemoveOrg wipes one org directory (key first) and removes the folder.
// If it was active, active is cleared — we do not silently switch.
func RemoveOrg(root, orgID string) error {
	dir := OrgDir(root, orgID)
	first := ClearOrgDir(dir)
	if err := os.RemoveAll(dir); err != nil && first == nil {
		first = err
	}
	active, _ := ReadActive(root)
	if active == orgID {
		if err := ClearActive(root); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func FormatList(orgs []Enrollment) string {
	var b strings.Builder
	for _, o := range orgs {
		mark := " "
		if o.Active {
			mark = "*"
		}
		name := o.Name
		if strings.TrimSpace(name) == "" {
			name = "—"
		}
		slug := o.Slug
		if strings.TrimSpace(slug) == "" {
			slug = "—"
		}
		fmt.Fprintf(&b, "%s %s  %s  %s\n", mark, o.ID, name, slug)
	}
	return b.String()
}

// FormatJSON is the -json body for `list`. Empty input is [] not null.
func FormatJSON(orgs []Enrollment) ([]byte, error) {
	if orgs == nil {
		orgs = []Enrollment{}
	}
	return json.Marshal(orgs)
}

// PrintList writes FormatList, or FormatJSON when asJSON is set.
// Zero orgs with asJSON writes [] and succeeds; without asJSON it
// returns the existing enroll error (stdout stays empty).
func PrintList(out io.Writer, orgs []Enrollment, asJSON bool) error {
	if asJSON {
		raw, err := FormatJSON(orgs)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(raw))
		return err
	}
	if len(orgs) == 0 {
		return fmt.Errorf("no enrolled organizations — run `agent enroll`")
	}
	_, err := fmt.Fprint(out, FormatList(orgs))
	return err
}

func Match(orgs []Enrollment, query string) (Enrollment, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return Enrollment{}, fmt.Errorf("organization is required")
	}
	var hits []Enrollment
	for _, o := range orgs {
		if o.ID == q || strings.EqualFold(o.ID, q) || strings.EqualFold(o.Name, q) || strings.EqualFold(o.Slug, q) {
			hits = append(hits, o)
		}
	}
	if len(hits) == 0 {
		return Enrollment{}, fmt.Errorf("no enrolled organization matches %q", q)
	}
	var idHits []Enrollment
	for _, o := range hits {
		if o.ID == q || strings.EqualFold(o.ID, q) {
			idHits = append(idHits, o)
		}
	}
	if len(idHits) == 1 {
		return idHits[0], nil
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	ids := make([]string, 0, len(hits))
	for _, o := range hits {
		ids = append(ids, o.ID)
	}
	return Enrollment{}, fmt.Errorf("ambiguous organization %q: %s", q, strings.Join(ids, ", "))
}

func SwitchTo(root, query string) (Enrollment, error) {
	orgs, err := List(root)
	if err != nil {
		return Enrollment{}, err
	}
	if len(orgs) == 0 {
		return Enrollment{}, fmt.Errorf("no enrolled organizations — run `agent enroll`")
	}
	got, err := Match(orgs, query)
	if err != nil {
		return Enrollment{}, err
	}
	if err := WriteActive(root, filepath.Base(got.Dir)); err != nil {
		return Enrollment{}, err
	}
	got.Active = true
	return got, nil
}
