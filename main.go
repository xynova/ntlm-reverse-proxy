package main

import (
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"github.com/xynova/ntlm-reverse-proxy/pkg/transport"
	"github.com/xynova/ntlm-reverse-proxy/pkg/authenticator"
	"fmt"
	"os"
	"strings"
)



func main() {

	//panic("inconceivable")

	config, err := parseProxyConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Set log level
	switch lvl := strings.ToLower(config.logLevel) ; lvl {
		case "debug":
			log.SetLevel(log.DebugLevel)
		case "error":
			log.SetLevel(log.ErrorLevel)
		default:
			log.SetLevel(log.InfoLevel)
	}


	// Create NTLM transport
	authenticator := authenticator.NewNtlmAuthenticator( config.username, config.password )
	transport := transport.NewNtlmTransport(authenticator, transport.DefaultHttpTransportFactory)

	// Create reverse proxy with NTLM transport
	proxy := httputil.NewSingleHostReverseProxy(config.targetUrl)
	proxy.Transport = transport
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Errorf("http: proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
	}

	// Start server
	listenAddr := fmt.Sprintf("%s:%d",config.address,config.port)
	log.Infof("Starting unencrypted listener on %s:",listenAddr)
	log.Fatal(http.ListenAndServe( listenAddr, http.Handler(proxy)))
}

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{
		  	FieldMap: log.FieldMap{
				log.FieldKeyTime:  "timestamp",
		   },
	})

	log.SetLevel(log.InfoLevel)
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

}