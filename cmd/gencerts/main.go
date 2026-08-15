package main

import (
	"flag"
	"log"
	"os"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func main() {
	dir := flag.String("dir", "certs", "output directory for throwaway test PEMs")
	flag.Parse()

	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		log.Fatal(err)
	}
	if err := pki.WriteDir(*dir); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote test PKI to %s (CA, server SAN=localhost, client CN=%s OU=%s)",
		*dir, mtls.TestClientCN, mtls.TestClientOU)
	os.Exit(0)
}
