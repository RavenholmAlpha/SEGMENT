// segment-client runs the local SOCKS5 ingress backed by the Segment
// tunnel.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"segment/internal/client"
	"segment/internal/config"
)

// loadCA loads a PEM CA bundle for server verification.
func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates found in " + path)
	}
	return pool, nil
}

func main() {
	var (
		confFile = flag.String("config", "", "YAML config file (flags override it)")

		server      = flag.String("server", "", "segment server host:port")
		sni         = flag.String("sni", "", "TLS SNI / :authority (default: server host)")
		psk         = flag.String("psk", "", "pre-shared key (>= 32 bytes)")
		socks       = flag.String("socks", "", "SOCKS5 listen address (default 127.0.0.1:1080)")
		insecure    = flag.Bool("insecure", false, "skip TLS certificate verification (dev)")
		certFile    = flag.String("cacert", "", "optional CA bundle for verification")
		credFile    = flag.String("cred", "", "session credential cache file (enables persistence)")
		fingerprint = flag.String("tls-fingerprint", "", "TLS ClientHello fingerprint: chrome (default) | go")
	)
	flag.Parse()

	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	changed := func(name string) bool { return set[name] }

	pc := config.Client{}
	if err := config.Load(*confFile, &pc, false); err != nil {
		log.Fatal(err.Error())
	}
	if changed("server") {
		pc.Server = *server
	}
	if changed("sni") {
		pc.SNI = *sni
	}
	if changed("psk") {
		pc.PSK = *psk
	}
	if changed("socks") {
		pc.SOCKS = *socks
	}
	if pc.SOCKS == "" {
		pc.SOCKS = "127.0.0.1:1080"
	}
	if changed("insecure") {
		pc.Insecure = *insecure
	}
	if changed("cacert") {
		pc.CAFile = *certFile
	}
	if changed("cred") {
		pc.CredFile = *credFile
	}
	if changed("tls-fingerprint") {
		pc.Fingerprint = *fingerprint
	}

	if err := config.ValidateClient(&pc); err != nil {
		log.Fatal(err.Error())
	}

	var tlsCfg *tls.Config
	if pc.CAFile != "" {
		pool, err := loadCA(pc.CAFile)
		if err != nil {
			log.Fatalf("load CA: %v", err)
		}
		tlsCfg = &tls.Config{RootCAs: pool}
	}

	c, err := client.NewWithPSK(client.Options{
		Server:      pc.Server,
		SNI:         pc.SNI,
		TLS:         tlsCfg,
		Insecure:    pc.Insecure,
		CredFile:    pc.CredFile,
		Fingerprint: pc.Fingerprint,
	}, []byte(pc.PSK))
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	if err := c.Connect(); err != nil {
		log.Fatalf("connect: %v", err)
	}
	log.Printf("tunnel ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = c.Close()
		os.Exit(0)
	}()

	if err := c.ServeSOCKS(pc.SOCKS); err != nil {
		log.Fatalf("socks5: %v", err)
	}
}
