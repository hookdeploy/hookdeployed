package sysinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/version"
)

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "ubuntu pretty",
			in:   "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
			want: "Ubuntu 24.04.1 LTS",
		},
		{
			name: "fallback id + version",
			in:   "ID=debian\nVERSION_ID=\"12\"\n",
			want: "debian 12",
		},
		{name: "empty", in: "", want: ""},
		{name: "comments only", in: "# just a comment\n", want: ""},
		{
			name: "unquoted",
			in:   "ID=alpine\nVERSION_ID=3.20.0\nPRETTY_NAME=Alpine Linux v3.20\n",
			want: "Alpine Linux v3.20",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseOSRelease(tc.in)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestParseSwVers(t *testing.T) {
	out := []byte("ProductName:\tmacOS\nProductVersion:\t15.2\nBuildVersion:\t24C101\n")
	if got := parseSwVers(out); got != "macOS 15.2" {
		t.Fatalf("got %q", got)
	}
	if got := formatDarwinVersion("", ""); got != "" {
		t.Fatalf("empty=%q", got)
	}
	if got := formatDarwinVersion("", "15.2"); got != "15.2" {
		t.Fatalf("ver only=%q", got)
	}
}

func TestFormatWindowsVersion(t *testing.T) {
	cases := []struct{ name, product, display, want string }{
		{"win11", "Windows 11 Pro", "23H2", "Windows 11 Pro 23H2"},
		{"already contains", "Windows 11 Pro 23H2", "23H2", "Windows 11 Pro 23H2"},
		{"no display", "Windows 10 Pro", "", "Windows 10 Pro"},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatWindowsVersion(tc.product, tc.display)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestCollectSane(t *testing.T) {
	info := Collect()
	if info.OS != runtime.GOOS {
		t.Fatalf("os=%q want %q", info.OS, runtime.GOOS)
	}
	if info.Arch != runtime.GOARCH {
		t.Fatalf("arch=%q want %q", info.Arch, runtime.GOARCH)
	}
	if info.AgentVersion != version.Version {
		t.Fatalf("agent_version=%q want %q", info.AgentVersion, version.Version)
	}
	switch runtime.GOOS {
	case "windows":
		if info.OSVersion == "" {
			t.Log("windows os_version empty (registry unreadable in this environment)")
		}
	case "linux", "darwin":
		// may be empty in CI containers without os-release / sw_vers
	}
	if info.Hostname == "" {
		t.Log("hostname empty")
	}
}

func TestClearStateRemovesSiblingFile(t *testing.T) {
	certs := filepath.Join(t.TempDir(), "certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		t.Fatal(err)
	}
	path := StatePath(certs)
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ClearState(certs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state still present: %v", err)
	}
	if err := ClearState(certs); err != nil {
		t.Fatalf("missing state must not error: %v", err)
	}
}

func TestStatePathOutsideCertStore(t *testing.T) {
	certs := filepath.Join(t.TempDir(), "hookdeploy", "certs")
	got := StatePath(certs)
	if filepath.Base(got) != "system-info.json" {
		t.Fatalf("base=%q", got)
	}
	if filepath.Dir(got) != filepath.Dir(certs) {
		t.Fatalf("state=%q should be sibling of certs=%q", got, certs)
	}
	if strings.Contains(got, string(filepath.Separator)+"certs"+string(filepath.Separator)) {
		t.Fatalf("state must not live inside the cert store: %q", got)
	}
}

func TestShouldSend(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	info := Info{Hostname: "h", OS: "linux", OSVersion: "Ubuntu 24.04.1 LTS", Arch: "amd64", AgentVersion: "dev"}
	agentID := "agent-1"

	if !shouldSend(snapshot{}, agentID, info, now) {
		t.Fatal("absent snapshot must send")
	}
	sent := markSent(agentID, info, now)
	if shouldSend(sent, agentID, info, now.Add(time.Hour)) {
		t.Fatal("unchanged values must not resend")
	}
	changed := info
	changed.Hostname = "other"
	if shouldSend(sent, agentID, changed, now) {
		t.Fatal("retry floor should suppress an immediate retry")
	}
	if !shouldSend(sent, agentID, changed, now.Add(RetryInterval)) {
		t.Fatal("changed value after retry floor must send")
	}
	if !shouldSend(sent, "agent-2", info, now.Add(RetryInterval)) {
		t.Fatal("new agent id must send")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "system-info.json")
	info := Info{Hostname: "box", OS: "linux", Arch: "amd64", AgentVersion: "dev"}
	s := markSent("abc", info, time.Unix(100, 0))
	if err := writeSnapshot(path, s); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0077 == 0 && runtime.GOOS != "windows" {
		// 0644 is expected; not 0600
	}
	got, err := loadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != "abc" || got.Sent == nil || got.Sent.Hostname != "box" {
		t.Fatalf("roundtrip=%+v", got)
	}
}
