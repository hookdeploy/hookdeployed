package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func packagingDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func readRepo(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(packagingDir(t)), rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func TestDebconfEnrollTokenIsStringNotPassword(t *testing.T) {
	tpl := readRepo(t, "packaging/debian/hookdeployed.templates")
	if !strings.Contains(tpl, "Type: string") {
		t.Fatal("hookdeployed/enroll_token must be Type: string")
	}
	if strings.Contains(tpl, "Type: password") {
		t.Fatal("password type mangles 77–79 char hd_enroll_* tokens; must not be used")
	}
}

func TestProductionTokenLongerThanPasswordWidgetLimit(t *testing.T) {
	// Worker parseTokenRegion: ^hd_enroll_(us|eu|apac|au)_ + 64 hex.
	// Dialog/newt password widgets have historically truncated at 64.
	const hex = 64
	for _, prefix := range []string{"hd_enroll_us_", "hd_enroll_eu_", "hd_enroll_au_", "hd_enroll_apac_"} {
		n := len(prefix) + hex
		if n <= 64 {
			t.Fatalf("%s + 64 hex is %d chars; must exceed the 64-char password-widget limit", prefix, n)
		}
	}
}

func TestPostinstSourcesConfmoduleBeforeAnyStdout(t *testing.T) {
	postinst := readRepo(t, "packaging/debian/postinst")
	conf := strings.Index(postinst, ". /usr/share/debconf/confmodule")
	if conf < 0 {
		t.Fatal("postinst must source confmodule")
	}
	// Anything that writes to stdout before this source desynchronizes db_get
	// on the frontend re-exec (see packaging/lib/debconf_desync_test.sh).
	ensure := strings.Index(postinst, "ensure_user")
	common := strings.Index(postinst, ". \"${COMMON}\"")
	if ensure < 0 || common < 0 {
		t.Fatal("postinst missing ensure_user or COMMON source")
	}
	if conf > ensure || conf > common {
		t.Fatal("confmodule must be sourced before COMMON/ensure_user — those log to stdout")
	}
	if !strings.HasPrefix(strings.TrimSpace(postinst), "#!/bin/sh") {
		t.Fatal("unexpected postinst shebang")
	}
}

func TestPostinstEnrollFailureDoesNotFailPackage(t *testing.T) {
	postinst := readRepo(t, "packaging/debian/postinst")
	if !strings.Contains(postinst, "if enroll_with_token /usr/bin/hookdeployed") {
		t.Fatal("postinst must catch enroll_with_token failure")
	}
	if !strings.Contains(postinst, "enrollment did not succeed") {
		t.Fatal("postinst must log enroll failure and continue")
	}
	if !strings.Contains(postinst, "print_no_token_instructions") {
		t.Fatal("failed enroll must fall through to manual instructions")
	}
	if !strings.HasSuffix(strings.TrimSpace(postinst), "exit 0") {
		t.Fatal("postinst must end with exit 0")
	}
	// The old bug: set -e + die() inside enroll_with_token aborted configure.
	if strings.Contains(postinst, "enroll_with_token /usr/bin/hookdeployed \"${TOKEN}\"\n") &&
		!strings.Contains(postinst, "if enroll_with_token") {
		t.Fatal("uncaught enroll_with_token call would fail dpkg on a bad token")
	}
}

func TestInstallShTokenPathUnchanged(t *testing.T) {
	inst := readRepo(t, "install.sh")
	for _, want := range []string{
		`--token)`,
		`TOKEN="$2"`,
		`--token=*)`,
		`TOKEN="${1#--token=}"`,
		`enroll_with_token "${INSTALL_PATH}" "${TOKEN}"`,
	} {
		if !strings.Contains(inst, want) {
			t.Fatalf("install.sh --token path changed: missing %q", want)
		}
	}
	// Must still abort the script on enroll failure (set -e), not swallow it.
	if strings.Contains(inst, `enroll_with_token "${INSTALL_PATH}" "${TOKEN}" || true`) {
		t.Fatal("install.sh must not ignore enroll_with_token failure")
	}
}

func TestInstallShEmbeddedCopyMatchesLib(t *testing.T) {
	inst := readRepo(t, "install.sh")
	lib := readRepo(t, "packaging/lib/install-common.sh")
	start := strings.Index(inst, ". /dev/stdin <<'INSTALL_COMMON'\n")
	end := strings.Index(inst, "\nINSTALL_COMMON\n")
	if start < 0 || end < 0 {
		t.Fatal("install.sh missing INSTALL_COMMON heredoc markers")
	}
	start += len(". /dev/stdin <<'INSTALL_COMMON'\n")
	embedded := inst[start:end]
	lib = strings.TrimRight(lib, "\n") + "\n"
	embedded = strings.TrimRight(embedded, "\n") + "\n"
	if lib != embedded {
		t.Fatalf("install.sh inlined install-common.sh does not match packaging/lib/install-common.sh (%d vs %d bytes)", len(lib), len(embedded))
	}
}

func TestEnrollWithTokenPassesQuotedTrimmedTokenAndDoesNotDie(t *testing.T) {
	lib := readRepo(t, "packaging/lib/install-common.sh")
	if !strings.Contains(lib, `tr -d '\r\n'`) {
		t.Fatal("enroll_with_token must strip CR/LF before passing -token")
	}
	if !strings.Contains(lib, `enroll -token "${token}"`) {
		t.Fatal(`token must be a single quoted argv: enroll -token "${token}"`)
	}
	if strings.Contains(lib, `die "enroll failed`) {
		t.Fatal("enroll_with_token must return 1, not die(), on enroll failure")
	}
	if !strings.Contains(lib, "return 1") {
		t.Fatal("enroll_with_token must return 1 on enroll failure")
	}
}

func TestDebconfProtocolDesyncStealsTokenReply(t *testing.T) {
	// Models Debian confmodule's 1:1 command/reply on the protocol pipe.
	// A stdout log line before sourcing confmodule is read as a command;
	// db_get then consumes that error reply. The stored token is never read.
	// Worker parseTokenRegion fails → 401 "invalid token".
	const good = "hd_enroll_us_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	frontend := func(cmd string) string {
		if strings.HasPrefix(cmd, "GET") {
			return "0 " + good
		}
		return "20 not-a-command"
	}
	strip := func(line string) string {
		if len(line) >= 2 && line[0] != ' ' && line[1] == ' ' {
			return line[2:]
		}
		return line
	}
	stolen := strip(frontend("hookdeployed: user hookdeployed already exists"))
	_ = frontend("GET hookdeployed/enroll_token") // unread, like the real pipe
	fixed := strip(frontend("GET hookdeployed/enroll_token"))
	if stolen == good {
		t.Fatal("polluted protocol should not yield the stored token")
	}
	if strings.HasPrefix(stolen, "hd_enroll_") {
		t.Fatalf("stolen RET still looks like a token: %q", stolen)
	}
	if fixed != good {
		t.Fatalf("clean GET should return the stored token, got %q", fixed)
	}
}

func TestMangledTokenStillLooksValidToWorkerPrefix(t *testing.T) {
	// enrollment-worker parseTokenRegion: prefix match OR hash miss → 401 "invalid token".
	// A truncated or CR-suffixed token still matches the prefix, so the agent
	// prints "invalid token" (hash miss), not a client-side format error.
	re := regexp.MustCompile(`^hd_enroll_(us|eu|apac|au)_`)
	full := "hd_enroll_apac_" + strings.Repeat("a", 64)
	if !re.MatchString(full) {
		t.Fatal("fixture token must match parseTokenRegion")
	}
	truncated := full[:64]
	if len(truncated) != 64 || !re.MatchString(truncated) {
		t.Fatal("64-char truncation still matches the prefix — that is the password-widget failure mode")
	}
	if !re.MatchString(full + "\r") {
		t.Fatal("token+CR still matches the prefix — worker hashes the CR and returns invalid token")
	}
}

func TestEnrollBehavior(t *testing.T) {
	bash := usableBash()
	if bash == "" {
		t.Skip("usable bash not available")
	}
	for _, name := range []string{"enroll_behavior_test.sh", "debconf_desync_test.sh"} {
		script := filepath.Join(packagingDir(t), "lib", name)
		cmd := exec.Command(bash, script)
		cmd.Dir = filepath.Dir(packagingDir(t))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		if !strings.Contains(string(out), "ok") {
			t.Fatalf("%s unexpected output:\n%s", name, out)
		}
	}
}

func usableBash() string {
	bash, err := exec.LookPath("bash")
	if err != nil {
		return ""
	}
	// WSL's system32\bash.exe launcher cannot exec POSIX scripts from this host.
	if strings.Contains(strings.ToLower(bash), `system32`+string(os.PathSeparator)+`bash.exe`) {
		return ""
	}
	return bash
}
