package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Tray cross-reference: hookdeploy-tray/src-tauri/src/supervisor.rs
//   default_certs_dir_matches_hookdeployed_user_config_dir_on_{windows,darwin,linux}
// Each case uses the same os.UserConfigDir base the tray tests derive from
// APPDATA / HOME+Library/Application Support / XDG_CONFIG_HOME|HOME/.config.
func TestCertDirFromUserConfigMatchesTrayContract(t *testing.T) {
	cases := []struct {
		name       string
		userConfig string
		want       string
	}{
		{
			name:       "windows_APPDATA",
			userConfig: filepath.Join("C:", "Users", "alice", "AppData", "Roaming"),
			want:       filepath.Join("C:", "Users", "alice", "AppData", "Roaming", "hookdeploy", "certs"),
		},
		{
			name:       "darwin_Application_Support",
			userConfig: filepath.Join("/Users", "alice", "Library", "Application Support"),
			want:       filepath.Join("/Users", "alice", "Library", "Application Support", "hookdeploy", "certs"),
		},
		{
			name:       "linux_HOME_dot_config",
			userConfig: filepath.Join("/home", "alice", ".config"),
			want:       filepath.Join("/home", "alice", ".config", "hookdeploy", "certs"),
		},
		{
			name:       "linux_XDG_CONFIG_HOME",
			userConfig: "/custom/xdg-config",
			want:       filepath.Join("/custom/xdg-config", "hookdeploy", "certs"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := certDirFromUserConfig(tc.userConfig)
			if got != tc.want {
				t.Fatalf("certDirFromUserConfig(%q)=%q want %q", tc.userConfig, got, tc.want)
			}
		})
	}
}

func TestDefaultDirFromUserConfigFallback(t *testing.T) {
	if got := defaultDirFromUserConfig("", os.ErrNotExist); got != "certs" {
		t.Fatalf("error path=%q want certs", got)
	}
	if got := defaultDirFromUserConfig("", nil); got != "certs" {
		t.Fatalf("empty path=%q want certs", got)
	}
	base := filepath.Join("/tmp", "user-config")
	if got := defaultDirFromUserConfig(base, nil); got != certDirFromUserConfig(base) {
		t.Fatalf("got %q want %q", got, certDirFromUserConfig(base))
	}
}

func TestDefaultDirHonorsHookdeployCertDirOverride(t *testing.T) {
	const override = "/var/lib/hookdeployed/certs"
	t.Setenv("HOOKDEPLOY_CERT_DIR", override)
	if got := DefaultDir(); got != override {
		t.Fatalf("DefaultDir()=%q want HOOKDEPLOY_CERT_DIR=%q", got, override)
	}
}

func TestDefaultDirOnCurrentPlatformMatchesUserConfigDir(t *testing.T) {
	t.Setenv("HOOKDEPLOY_CERT_DIR", "")

	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	want := certDirFromUserConfig(base)
	if got := DefaultDir(); got != want {
		t.Fatalf("DefaultDir()=%q want %q (UserConfigDir=%q GOOS=%s)", got, want, base, runtime.GOOS)
	}
}
