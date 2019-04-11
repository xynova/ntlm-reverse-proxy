package transport

import (
	"net/http"
	"io"
	"io/ioutil"
	"bytes"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/ntlm-reverse-proxy/pkg/authenticator"
)



// NTLM2 transport
func NewNtlmTransport( authenticator authenticator.Authenticator, factory HttpTransportFactory) http.RoundTripper {
	return  &ntlmTransport{
		Authenticator : authenticator,
		Factory: factory,
	}
}



// ntlmTransport is implementation of http.RoundTripper interface
type ntlmTransport struct {
	Authenticator authenticator.Authenticator
	Factory       HttpTransportFactory
}



// RoundTrip method send http request and tries to perform NTLM authentication
func (t *ntlmTransport) RoundTrip(req *http.Request) ( *http.Response,  error) {

	var (
		rt                   *http.Response
		err                  error
		bodyCopy             io.ReadCloser
		connectionAuthorized bool
		roundTripper         http.RoundTripper = t.Factory.NewTransport()
	)

	req.RequestURI = ""

	// If it is a POST action, make a copy of the body
	if req.Body != nil {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil  {
			return nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
		bodyCopy = ioutil.NopCloser(bytes.NewBuffer(buf))
		defer bodyCopy.Close()
	}



	// Try our luck, connection might be authenticated
	if rt, err = roundTripper.RoundTrip(req); err != nil  {
		return nil, err
	}

	// Pass-through if its not StatusUnauthorized
	if rt.StatusCode != http.StatusUnauthorized  {
		return rt, nil
	}




	// Try authorize request
	if rt.StatusCode == http.StatusUnauthorized {

		log.Debugf("%x: Try to authenticate connection to %s", &roundTripper, req.URL)
		// Ensure connection is reused
		if err = authenticator.CloseResponseBody(rt); err != nil {
			return nil, err
		}

		// try to authenticate connection
		if connectionAuthorized,err = t.Authenticator.TryAuthenticate(req.URL.String(), &roundTripper); err != nil {
			return nil, err
		}

		// Authorization did not succeed, return the first response
		if connectionAuthorized {
			log.Debugf("%x: Connection authorized, re-issuing request", &roundTripper)
		}


		if bodyCopy != nil {
			req.Body = bodyCopy
		}

		// re-issue request to return open response body
		if rt, err = roundTripper.RoundTrip(req); err != nil {
			return nil, err
		}

	}

	return rt, nil

}

