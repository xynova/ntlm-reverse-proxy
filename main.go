package main

import (
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"github.com/xynova/ntlm-reverse-proxy/pkg/transport"
	"github.com/xynova/ntlm-reverse-proxy/pkg/authenticator"
	"fmt"
	"os"
)



func main() {

	config, err := parseProxyConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Create NTLM transport
	authenticator := authenticator.NewNtlmAuthenticator( config.username, config.password )
	transport := transport.NewNtlmTransport(authenticator, transport.DefaultHttpTransportFactory)

	// Create reverse proxy with NTLM transport
	proxy := httputil.NewSingleHostReverseProxy(config.targetUrl)
	proxy.Transport = transport

	// Start server
	listenAddr := fmt.Sprintf("%s:%d",config.address,config.port)
	log.Printf("Starting unencrypted listener on %s:",listenAddr)
	log.Fatal(http.ListenAndServe( listenAddr, http.Handler(proxy)))
}

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	//log.SetLevel(log.WarnLevel)
}