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
	runEcho()
}

func runEnroll() error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	baseURL := fs.String("enroll-url", "https://enroll.hookdeploy.dev", "enrollment worker base URL")
	org := fs.String("org", "", "organization slug (required for device-code)")
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
	if *org == "" {
		return fmt.Errorf("device-code enroll requires -org <slug> (or pass -token)")
	}
	if err := enroll.RunDevice(*baseURL, *org, *dir); err != nil {
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

func confirmStore(dir string) error {
	material, err := store.Load(dir)
	if err != nil {
		return err
	}
	cn := material.ClientCert.Subject.CommonName
	ou := ""
	if len(material.ClientCert.Subject.OrganizationalUnit) > 0 {
		ou = material.ClientCert.Subject.OrganizationalUnit[0]
	}
	log.Printf("stored cert in %s CN=%s OU=%s", dir, cn, ou)
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
