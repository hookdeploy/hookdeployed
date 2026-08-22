package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hookdeploy/hookdeployed/internal/connect"
	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

func init() {
	log.SetFlags(0)
	log.SetPrefix("agent: ")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		if err := runEnroll(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "connect" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		if err := runConnect(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "list" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		if err := runList(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "switch" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		if err := runSwitch(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "unenroll" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		if err := runUnenroll(); err != nil {
			log.Fatal(err)
		}
		return
	}
	runEcho()
}

func runEnroll() error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	baseURL := fs.String("enroll-url", "https://enroll.hookdeploy.dev", "enrollment worker base URL")
	token := fs.String("token", "", "one-time enrollment token (scripted/CI)")
	dir := fs.String("certs", store.DefaultDir(), "cert store directory (0600 files)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *token != "" {
		if err := enroll.RunToken(*baseURL, *token, *dir); err != nil {
			return err
		}
		return confirmStore(*dir)
	}
	if err := enroll.RunDevice(*baseURL, *dir); err != nil {
		return err
	}
	return confirmStore(*dir)
}

func runConnect() error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	relay := fs.String("relay", "", "relay host or host:port (default port 9443)")
	dir := fs.String("certs", store.DefaultDir(), "cert store directory (0600 files)")
	enrollURL := fs.String("enroll-url", "https://enroll.hookdeploy.dev", "enrollment worker for renewal")
	interval := fs.Duration("ping-interval", connect.DefaultPingInterval, "PING interval")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *relay == "" {
		return fmt.Errorf("--relay is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return connect.Run(ctx, connect.Config{
		Relay:        *relay,
		CertsDir:     *dir,
		EnrollURL:    *enrollURL,
		PingInterval: *interval,
	})
}

func runList() error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	orgs, err := store.List(*dir)
	if err != nil {
		return err
	}
	if len(orgs) == 0 {
		return fmt.Errorf("no enrolled organizations — run `agent enroll`")
	}
	fmt.Print(store.FormatList(orgs))
	return nil
}

func runUnenroll() error {
	fs := flag.NewFlagSet("unenroll", flag.ExitOnError)
	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
	enrollURL := fs.String("enroll-url", "https://enroll.hookdeploy.dev", "enrollment worker for self-revoke")
	localOnly := fs.Bool("local-only", false, "delete local credentials without revoking the agent")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	tty := enroll.RequireInteractiveFile(os.Stdin) == nil
	query := strings.Join(fs.Args(), " ")
	return enroll.Unenroll(enroll.UnenrollConfig{
		Root:      *dir,
		EnrollURL: *enrollURL,
		LocalOnly: *localOnly,
		Yes:       *yes,
		Query:     query,
	}, os.Stdin, os.Stdout, tty)
}

func runSwitch() error {
	fs := flag.NewFlagSet("switch", flag.ExitOnError)
	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	tty := enroll.RequireInteractiveFile(os.Stdin) == nil
	return store.RunSwitch(*dir, fs.Args(), os.Stdin, os.Stdout, tty)
}

func confirmStore(dir string) error {
	orgDir, err := store.ResolveActiveDir(dir)
	if err != nil {
		return store.ExplainResolve(dir, err)
	}
	material, err := store.Load(orgDir)
	if err != nil {
		return err
	}
	cn := material.ClientCert.Subject.CommonName
	ou := ""
	if len(material.ClientCert.Subject.OrganizationalUnit) > 0 {
		ou = material.ClientCert.Subject.OrganizationalUnit[0]
	}
	if meta, err := store.LoadOrgMeta(orgDir); err == nil && meta.Name != "" {
		log.Printf("stored cert in %s org=%s CN=%s OU=%s", orgDir, meta.Name, cn, ou)
	} else {
		log.Printf("stored cert in %s CN=%s OU=%s", orgDir, cn, ou)
	}
	if cn == "" || ou == "" {
		return fmt.Errorf("enrolled cert missing CN or OU — relay will reject")
	}
	return nil
}

func runEcho() {
	addr := flag.String("addr", mtls.DefaultListenAddr, "relay-stub address")
	dir := flag.String("certs", "certs", "directory with ca.crt, client.crt, client.key")
	line := flag.String("line", "hello-from-agent", "line to send (newline appended)")
	enrollURL := flag.String("enroll-url", "https://enroll.hookdeploy.dev", "enrollment worker for renewal")
	flag.Parse()

	if _, err := mtls.LoadClientDir(*dir); err == nil {
		if err := enroll.MaybeRenew(*enrollURL, *dir); err != nil {
			log.Printf("renew skipped/failed: %v", err)
		}
		pki, err := mtls.LoadClientDir(*dir)
		if err != nil {
			log.Fatalf("load certs: %v", err)
		}
		dialAndEcho(*addr, *line, pki.ClientTLSConfig())
		return
	}

	pki, err := mtls.LoadDir(*dir)
	if err != nil {
		log.Fatalf("load certs: %v", err)
	}
	dialAndEcho(*addr, *line, pki.ClientTLSConfig())
}

func dialAndEcho(addr, line string, cfg *tls.Config) {
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sent := line + "\n"
	if _, err := fmt.Fprint(conn, sent); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("sent: %q", sent)

	echo, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatalf("read echo: %v", err)
	}
	log.Printf("echo: %q", echo)

	if echo != sent {
		log.Fatalf("echo mismatch: sent %q got %q", sent, echo)
	}
	log.Printf("mTLS echo ok")
	os.Exit(0)
}
