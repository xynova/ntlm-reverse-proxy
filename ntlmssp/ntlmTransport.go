package ntlmssp

import (
	"net/http"
	"io"
	"io/ioutil"
	"bytes"
	"log"
)





// ntlmTransport is implementation of http.RoundTripper interface
type ntlmTransport struct {
	Authenticator ConnectionAuthenticator
	Client        *http.Client
}


// RoundTrip method send http request and tries to perform NTLM authentication
func (t *ntlmTransport) RoundTrip(req *http.Request) ( *http.Response,  error) {

	var (
		rt       *http.Response
		err      error
		bodyCopy io.ReadCloser
		connectionAuthorized bool
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
	if rt, err = t.Client.Do(req); err != nil  {
		return nil, err
	}

	// Pass-through if its not StatusUnauthorized
	if rt.StatusCode != http.StatusUnauthorized  {
		return rt, nil
	}


	// Try authorize request
	if rt.StatusCode == http.StatusUnauthorized {

		log.Print("Try to authenticate connection")
		// Ensure connection is reused
		if err = closeResponseBody(rt); err != nil {
			return nil, err
		}

		// try to authenticate connection
		if connectionAuthorized,err = t.Authenticator.TryAuthenticate(req.URL.String(), t.Client); err != nil {
			return nil, err
		}

		if connectionAuthorized {
			log.Print("Connection authenticated")
		}

		if bodyCopy != nil {
			req.Body = bodyCopy
		}

		// re-issue request
		if rt, err = t.Client.Do(req); err != nil {
			return nil, err
		}
	}

	return rt, nil

}

