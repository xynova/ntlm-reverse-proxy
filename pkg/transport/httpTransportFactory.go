package transport

import (
	"net/http"
	"net"
	"time"
)


type HttpTransportFactory interface {
	NewTransport() *http.Transport
}

var DefaultHttpTransportFactory HttpTransportFactory = &httpTransportFactory{
	dialer: &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	},
}


type httpTransportFactory struct {
	dialer *net.Dialer
}

func (f *httpTransportFactory) NewTransport() *http.Transport  {
	return &http.Transport{
		MaxIdleConns:           10,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		DialContext: 			f.dialer.DialContext,
	}
}

