// segment-server runs the caddy-like Segment fronting server: a fake
// video site for everyone, a tunnel only for authenticated clients.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"time"

	"segment/internal/auth"
	"segment/internal/config"
	"segment/internal/server"
	"segment/internal/tunnel"
)

// tlsCert aliases the TLS certificate type used by the loader.
type tlsCert = tls.Certificate

// loadCert loads a PEM certificate/key pair.
func loadCert(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func main() {
	var (
		confFile = flag.String("config", "", "YAML config file (flags override it)")

		listen   = flag.String("listen", "", "listen address (default :443)")
		certFile = flag.String("cert", "", "TLS certificate file (PEM)")
		keyFile  = flag.String("key", "", "TLS private key file (PEM)")
		psk      = flag.String("psk", "", "pre-shared key (>= 32 bytes)")
		insecure = flag.Bool("insecure", false, "use an ephemeral self-signed certificate (dev)")

		pacing      = flag.Bool("pacing", true, "shape tunnel egress like media streaming")
		pacingBurst = flag.Int("pacing-burst", 256, "pacing burst size (KB)")
		pacingMin   = flag.Int("pacing-min-ms", 2, "pacing minimum pause between bursts (ms)")
		pacingMax   = flag.Int("pacing-max-ms", 8, "pacing maximum pause between bursts (ms)")
	)
	flag.Parse()

	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	changed := func(name string) bool { return set[name] }

	// File defaults, then flag overrides.
	pc := config.Server{}
	if err := config.Load(*confFile, &pc, false); err != nil {
		log.Fatal(err.Error())
	}
	if changed("listen") {
		pc.Listen = *listen
	} else if pc.Listen == "" {
		pc.Listen = ":443"
	}
	if changed("cert") {
		pc.Cert = *certFile
	}
	if changed("key") {
		pc.Key = *keyFile
	}
	if changed("psk") {
		pc.PSK = *psk
	}
	if changed("insecure") {
		pc.Insecure = *insecure
	}
	if changed("pacing") {
		pc.Pacing.Enabled = *pacing
	}
	if changed("pacing-burst") {
		pc.Pacing.BurstKB = *pacingBurst
	}
	if changed("pacing-min-ms") {
		pc.Pacing.MinPauseMS = *pacingMin
	}
	if changed("pacing-max-ms") {
		pc.Pacing.MaxPauseMS = *pacingMax
	}
	// Pacing defaults: enabled with the standard shape unless the file
	// or flags said otherwise.
	if pc.Pacing.BurstKB == 0 {
		pc.Pacing.BurstKB = 256
	}
	if pc.Pacing.MinPauseMS == 0 {
		pc.Pacing.MinPauseMS = 2
	}
	if pc.Pacing.MaxPauseMS == 0 {
		pc.Pacing.MaxPauseMS = 8
	}
	if pc.Pacing.Enabled && pc.Pacing.MaxPauseMS < pc.Pacing.MinPauseMS {
		log.Fatal("config: pacing min_pause_ms must not exceed max_pause_ms")
	}

	if err := config.ValidateServer(&pc); err != nil {
		log.Fatal(err.Error())
	}

	p := tunnel.Pacing{}
	if pc.Pacing.Enabled {
		p = tunnel.Pacing{
			Enabled:  true,
			Burst:    pc.Pacing.BurstKB << 10,
			MinPause: time.Duration(pc.Pacing.MinPauseMS) * time.Millisecond,
			MaxPause: time.Duration(pc.Pacing.MaxPauseMS) * time.Millisecond,
		}
	}

	var cert tlsCert
	switch {
	case pc.Insecure:
		c, err := server.SelfSignedCert()
		if err != nil {
			log.Fatalf("self-signed cert: %v", err)
		}
		cert = c
	case pc.Cert != "" && pc.Key != "":
		c, err := loadCert(pc.Cert, pc.Key)
		if err != nil {
			log.Fatalf("load cert: %v", err)
		}
		cert = c
	default:
		log.Fatal("provide cert/key (file or flags) or use -insecure")
	}

	authSrv, err := auth.NewServer([]byte(pc.PSK), config.TicketTTL, 30*time.Second, nil)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	raw, err := net.Listen("tcp", pc.Listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	ln := server.TLSListener(raw, cert)
	log.Printf("Segment server listening on %s", pc.Listen)

	err = server.Serve(ln, server.Options{Auth: authSrv, Pacing: p})
	log.Fatalf("serve: %v", err)
}
