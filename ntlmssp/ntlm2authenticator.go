package ntlmssp

import (
	"encoding/binary"
	"net/http"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	"strings"
	"errors"
	"log"
)

const (
	negotiateUnicode    = 0x00000001 // Text strings are in unicode
	negotiateOEM        = 0x00000002 // Text strings are in OEM
	requestTarget       = 0x00000004 // Server return its auth realm
	negotiateNTLM       = 0x00000200 // NTLM authentication
	negotiateAlwaysSign = 0x00008000 // Sign for all security levels
	negotiateNTLM2Key 	= 0x00080000
)

const (
	authHeaderKey         = "Authorization"
	authenticateHeaderKey = "WWW-Authenticate"
	ntlmHeaderValuePrefix = "NTLM "
)

type ntlm2Authenticator struct {
	username string
	password string
}

func (a *ntlm2Authenticator) TryAuthenticate(url string,  client *http.Client) ( success bool, err error ){

	var(
		challengeBytes []byte
		challengeMgs *ntlm.ChallengeMessage
		session ntlm.ClientSession
		userAuthMsg *ntlm.AuthenticateMessage
	)

	// Trigger a ntlm challenge from the server
	if challengeBytes, err = a.execChallengeRequest(url, client); err != nil {
		return false, err
	}

	// parse NTLM challenge and prepare type3 message
	if challengeMgs, err = ntlm.ParseChallengeMessage(challengeBytes); err != nil {
		return false,  err
	}

	if session, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode); err != nil {
		return false, err
	}

	session.SetUserInfo(a.username, a.password, "")
	if err = session.ProcessChallengeMessage(challengeMgs); err != nil {
		return false, err
	}

	if userAuthMsg, err = session.GenerateAuthenticateMessage(); err != nil {
		return false, err
	}

	if success, err = a.execAuthRequest(url, userAuthMsg, client); err != nil {
		return false, err
	}

	return success,nil
}

func (a *ntlm2Authenticator) getNTLM2NegotiateMsg() []byte {

	var (
		put32     = binary.LittleEndian.PutUint32
		put16     = binary.LittleEndian.PutUint16
	)

	ret := make([]byte, 44)
	flags := negotiateAlwaysSign | negotiateNTLM | requestTarget | negotiateOEM | negotiateUnicode | negotiateNTLM2Key

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], uint32(flags))   // flags
	put16(ret[16:], 0)               // NT domain name length
	put16(ret[18:], 0)               // NT domain name max length
	put32(ret[20:], 0)               // NT domain name offset
	put16(ret[24:], 0)               // local workstation name length
	put16(ret[26:], 0)               // local workstation name max length
	put32(ret[28:], 0)               // local workstation name offset
	put16(ret[32:], 0)               // unknown name length
	put16(ret[34:], 0)               // ...
	put16(ret[36:], 0x30)            // unknown offset
	put16(ret[38:], 0)               // unknown name length
	put16(ret[40:], 0)               // ...
	put16(ret[42:], 0x30)            // unknown offset

	return ret
}

func (a *ntlm2Authenticator) execChallengeRequest(url string, client *http.Client) (challengeBytes []byte, err  error ) {

	var(
		resp      *http.Response
		challenge string


	)


	msg1Req, _ := http.NewRequest("GET", url, strings.NewReader(""))

	type1Header := ntlmHeaderValuePrefix + encBase64(a.getNTLM2NegotiateMsg())
	msg1Req.Header.Add(authHeaderKey, type1Header)

	log.Print("Negotiate NTML challenge")
	if resp, err = client.Do(msg1Req); err != nil {
		return nil, err
	}

	// Ensure connection is reused
	if err = closeResponseBody(resp); err != nil {
		return nil, err
	}

	// retrieve Www-TryAuthenticate header from response
	type2Header := resp.Header.Get(authenticateHeaderKey)
	if type2Header == "" {
		return nil, errors.New("Empty "+ authenticateHeaderKey +" header")
	}

	challenge = strings.Replace(type2Header, ntlmHeaderValuePrefix, "", -1)
	if challengeBytes, err = decBase64(challenge); err != nil {
		return nil, err
	}

	return challengeBytes, nil
}

func (a *ntlm2Authenticator) execAuthRequest(url string, userAuthMsg *ntlm.AuthenticateMessage, client *http.Client) ( success bool, err  error ) {

	var(
		resp      *http.Response
	)

	msg3Req, _ := http.NewRequest("GET", url, strings.NewReader(""))

	type3Header :=  ntlmHeaderValuePrefix + encBase64(userAuthMsg.Bytes())
	msg3Req.Header.Set(authHeaderKey, type3Header)

	log.Print("Respond to NTML challenge")
	if resp, err = client.Do(msg3Req); err != nil {
		return false, err
	}
	if err = closeResponseBody(resp); err != nil {
		return false,  err
	}

	return resp.StatusCode == http.StatusOK, nil
}
