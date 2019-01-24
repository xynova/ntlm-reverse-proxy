package authenticator

import "net/http"

type Authenticator interface {
	TryAuthenticate(url string,  rt *http.RoundTripper) ( success bool, err error )
}

