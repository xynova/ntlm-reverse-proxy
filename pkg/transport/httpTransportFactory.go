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

		// KeepAlive: 30 * time.Second,
		// New settings because we use one new transport connection per request
		KeepAlive: 0 * time.Second,

		DualStack: true,
	},
}


type httpTransportFactory struct {
	dialer *net.Dialer
}

func (f *httpTransportFactory) NewTransport() *http.Transport  {
	return &http.Transport{

		//MaxIdleConns:           10,
		// IdleConnTimeout:        90 * time.Second,
		// New settings because we use one new transport per request
		MaxIdleConns:           1,
		IdleConnTimeout:        5 * time.Second,

		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		DialContext: 			f.dialer.DialContext,
	}
}

