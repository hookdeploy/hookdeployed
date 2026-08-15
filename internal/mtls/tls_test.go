package mtls

import (
	"crypto/tls"
	"io"
	"testing"
)

func TestRejectsConnectionWithoutClientCert(t *testing.T) {
	pki, err := GenerateTestPKI()
	if err != nil {
		t.Fatalf("generate test PKI: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- tlsConn.Handshake()
	}()

	cfg := &tls.Config{
		RootCAs:    pki.CAPool(),
		ServerName: DefaultServerName,
		MinVersion: tls.VersionTLS13,
	}

	conn, dialErr := tls.Dial("tcp", ln.Addr().String(), cfg)
	if dialErr != nil {
		t.Logf("client rejected at dial: %v", dialErr)
	} else {
		defer conn.Close()
		_, writeErr := conn.Write([]byte("should-fail\n"))
		if writeErr == nil {
			buf := make([]byte, 64)
			_, readErr := conn.Read(buf)
			if readErr == nil {
				t.Fatal("expected connection without a client certificate to be rejected")
			}
			t.Logf("client rejected at read: %v", readErr)
		} else {
			t.Logf("client rejected at write: %v", writeErr)
		}
	}

	serverErr := <-errCh
	if serverErr == nil {
		t.Fatal("expected server handshake to fail without a client certificate")
	}
	t.Logf("server rejected as expected: %v", serverErr)
}
