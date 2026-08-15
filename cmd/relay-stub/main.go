package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"os"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func main() {
	addr := flag.String("addr", mtls.DefaultListenAddr, "listen address")
	dir := flag.String("certs", "certs", "directory with ca.crt, server.crt, server.key")
	flag.Parse()

	pki, err := mtls.LoadDir(*dir)
	if err != nil {
		log.Fatalf("load certs: %v", err)
	}

	ln, err := tls.Listen("tcp", *addr, pki.ServerTLSConfig())
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("relay-stub listening on %s (mTLS required)", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn io.ReadWriteCloser) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("accept: not a TLS connection")
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("handshake failed: %v", err)
		return
	}

	cn, ou, err := mtls.ClientIdentity(tlsConn.ConnectionState())
	if err != nil {
		log.Printf("identity: %v", err)
		return
	}
	log.Printf("client identity CN=%s OU=%s", cn, ou)

	line, err := bufio.NewReader(tlsConn).ReadString('\n')
	if err != nil {
		log.Printf("read: %v", err)
		return
	}
	log.Printf("received: %q", line)
	if _, err := io.WriteString(tlsConn, line); err != nil {
		log.Printf("echo: %v", err)
		return
	}
	log.Printf("echoed; holding connection open")
	_, _ = io.Copy(io.Discard, tlsConn)
}

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("relay-stub: ")
}
