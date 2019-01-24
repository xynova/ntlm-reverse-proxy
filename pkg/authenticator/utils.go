package authenticator

import (
	"net/http"
	"io"
	"io/ioutil"
	"encoding/base64"
)


var (
	encBase64    = base64.StdEncoding.EncodeToString
	decodeBase64 = base64.StdEncoding.DecodeString
)



func CloseResponseBody(resp *http.Response) error {

	if resp.Body == nil {
		return nil
	}

	defer resp.Body.Close()

	if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
		return  err
	}

	return nil
}
