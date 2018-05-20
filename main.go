package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"github.com/xynova/ntlm-reverse-proxy/ntlmssp"
	"github.com/spf13/viper"
	"fmt"
	"errors"
)


type proxyConfig struct {
	address string
	port int
	username string
	password string
	targetUrl *url.URL
}


func main() {


	var (
		config *proxyConfig
		err error
	)

	if config, err = parseProxyConfig() ; err != nil {
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


func init(){
	viper.SetDefault("targetUrl","")
	viper.SetDefault("port","8080")
	viper.SetDefault("address","localhost")
	viper.SetDefault("username","")
	viper.SetDefault("password","")
	viper.AutomaticEnv()
}



func parseProxyConfig() (*proxyConfig, error){
	var (
		address   	= viper.GetString("address")
		port		= viper.GetInt("port")
		username    = viper.GetString("username")
		password 	= viper.GetString("password")
		targetUrl	= viper.GetString("targetUrl")
		uri *url.URL
		err error
	)



	if len(targetUrl) == 0 {
		return nil,errors.New("targetUrl cannot be empty")
	}

	if len(username) == 0 {
		return nil,errors.New("username cannot be empty")
	}

	if len(password) == 0 {
		return nil,errors.New("password cannot be empty")
	}

	// Configure reverse proxy
	if uri, err = url.ParseRequestURI(targetUrl); err != nil {
		return nil, err
	}

	rt := proxyConfig{
		address: address,
		port:port,
		username:username,
		password:password,
		targetUrl:uri,

	}

	return &rt, nil
}