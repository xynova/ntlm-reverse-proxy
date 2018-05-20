package ntlmssp

import (
	"net/http"
	"net"
	"time"
)


var DefaultClient *http.Client


func NewConnectionAuthenticator(username, password string) ConnectionAuthenticator {
	return &ntlm2Authenticator{
		username:username,
		password:password,
	}
}


func NewNtlmTransport( authenticator ConnectionAuthenticator, client *http.Client) http.RoundTripper {

	return  &ntlmTransport{
		Authenticator : authenticator,
		Client: client,
	}
}



type ConnectionAuthenticator interface {
	TryAuthenticate(url string,  client *http.Client) ( success bool, err error )
}


func init(){
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	transport := &http.Transport{
		MaxIdleConns:           10,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		DialContext: 			dialer.DialContext,
	}

	DefaultClient = &http.Client{
		Transport: transport,
	}
}