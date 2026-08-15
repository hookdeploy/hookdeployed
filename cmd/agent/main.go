package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func main() {
	addr := flag.String("addr", mtls.DefaultListenAddr, "relay-stub address")
	dir := flag.String("certs", "certs", "directory with ca.crt, client.crt, client.key")
	line := flag.String("line", "hello-from-agent", "line to send (newline appended)")
	flag.Parse()

	pki, err := mtls.LoadDir(*dir)
	if err != nil {
		log.Fatalf("load certs: %v", err)
	}

	conn, err := tls.Dial("tcp", *addr, pki.ClientTLSConfig())
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sent := *line + "\n"
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

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("agent: ")
}
