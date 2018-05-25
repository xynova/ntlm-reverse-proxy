package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"github.com/xynova/ntlm-reverse-proxy/ntlmssp"
	"fmt"
)



func main() {

	config, err := parseProxyConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Create NTLM transport
	authenticator := ntlmssp.NewConnectionAuthenticator( config.username, config.password )
	transport := ntlmssp.NewNtlmTransport(authenticator, ntlmssp.DefaultClient)

	// Create reverse proxy with NTLM transport
	proxy := httputil.NewSingleHostReverseProxy(config.targetUrl)
	proxy.Transport = transport

	// Start server
	listenAddr := fmt.Sprintf("%s:%d",config.address,config.port)
	log.Printf("Starting unencrpyed listener on %s:",listenAddr)
	log.Fatal(http.ListenAndServe( listenAddr, http.Handler(proxy)))
}
