package main

import (
	"flag"
	"log"
	"runtime"
	"time"

	"github.com/whiterabb17/gogencert/generator"
)

var (
	org        = flag.String("org", "Private Organization", "organization")
	host       = flag.String("host", "0.0.0.0", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
)

func main() {
	flag.Parse()

	if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}
	generator.Host = host
	generator.EcdsaCurve = ecdsaCurve
	generator.Org = org
	generator.ValidFor = validFor
	generator.ValidFrom = validFrom
	generator.RsaBits = rsaBits
	if runtime.GOOS == "windows" {
		generator.ExecStr = "bash"
	} else if runtime.GOOS == "linux" {
		generator.ExecStr = "/bin/bash"
	} else {
		generator.ExecStr = "/bin/zsh"
	}
	generator.Gen()
}
