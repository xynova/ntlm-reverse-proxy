package authenticator

import (
	"encoding/binary"
	"net/http"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	"strings"
	"errors"
	log "github.com/sirupsen/logrus"
)



const (
	authHeaderKey         = "Authorization"
	authenticateHeaderKey = "WWW-Authenticate"
	ntlmHeaderValuePrefix = "NTLM "
)


// NTLM2 web authenticator
func NewNtlmAuthenticator(username, password string) Authenticator {
	return &ntlm2Authenticator{
		Username:username,
		Password:password,
	}
}

type ntlm2Authenticator struct {
	Username string
	Password string
}

func (a *ntlm2Authenticator) TryAuthenticate(url string,  roundTripper *http.RoundTripper) ( success bool, err error ){

	var(
		challengeBytes []byte
		challengeMgs *ntlm.ChallengeMessage
		session ntlm.ClientSession
		userAuthMsg *ntlm.AuthenticateMessage
	)


	// Trigger a ntlm challenge from the server
	if challengeBytes, err = a.execChallengeRequest(url, roundTripper); err != nil {
		return false, err
	}

	// parse NTLM challenge and prepare type3 message
	if challengeMgs, err = ntlm.ParseChallengeMessage(challengeBytes); err != nil {
		return false,  err
	}

	if session, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode); err != nil {
		return false, err
	}

	session.SetUserInfo(a.Username, a.Password, "")
	if err = session.ProcessChallengeMessage(challengeMgs); err != nil {
		return false, err
	}

	if userAuthMsg, err = session.GenerateAuthenticateMessage(); err != nil {
		return false, err
	}

	if success, err = a.execAuthRequest(url, userAuthMsg, roundTripper); err != nil {
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
	flags := ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		ntlm.NTLMSSP_NEGOTIATE_NTLM |
		ntlm.NTLMSSP_REQUEST_TARGET |
		ntlm.NTLM_NEGOTIATE_OEM |
		ntlm.NTLMSSP_NEGOTIATE_UNICODE |
		ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY // negotiateNTLM2Key

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

func (a *ntlm2Authenticator) execChallengeRequest(url string, roundTripper *http.RoundTripper) (challengeBytes []byte, err  error ) {

	var(
		resp      *http.Response
		challenge string
	)

	msg1Req, _ := http.NewRequest("GET", url, strings.NewReader(""))

	type1Header := ntlmHeaderValuePrefix + encBase64(a.getNTLM2NegotiateMsg())
	msg1Req.Header.Add(authHeaderKey, type1Header)

	log.Printf("%x: Negotiate NTML challenge ", roundTripper)
	if resp, err =  (*roundTripper).RoundTrip(msg1Req); err != nil {
		return nil, err
	}

	// Ensure connection is reused
	if err = CloseResponseBody(resp); err != nil {
		return nil, err
	}

	// retrieve Www-TryAuthenticate header from response
	type2Header := resp.Header.Get(authenticateHeaderKey)
	if len(type2Header) < 10 {
		return nil, errors.New("Empty "+ authenticateHeaderKey +" header")
	}

	challenge = strings.Replace(type2Header, ntlmHeaderValuePrefix, "", -1)
	if challengeBytes, err = decodeBase64(challenge); err != nil {
		return nil, err
	}

	log.Printf("%x: Challenge received from server",  roundTripper)
	return challengeBytes, nil
}

func (a *ntlm2Authenticator) execAuthRequest(url string, userAuthMsg *ntlm.AuthenticateMessage, roundTripper *http.RoundTripper) ( success bool, err  error ) {

	var(
		resp      *http.Response
	)

	msg3Req, _ := http.NewRequest("GET", url, strings.NewReader(""))

	type3Header :=  ntlmHeaderValuePrefix + encBase64(userAuthMsg.Bytes())
	msg3Req.Header.Set(authHeaderKey, type3Header)

	log.Printf("%x: Respond to NTML challenge", roundTripper)
	if resp, err = (*roundTripper).RoundTrip(msg3Req); err != nil {
		return false, err
	}
	if err = CloseResponseBody(resp); err != nil {
		return false,  err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("%x: Challenge response was successful (%s)", roundTripper, resp.Status)
		return true, nil
	} else {
		log.Warnf("%x: The Challenge response was unsuccessful (%s)", roundTripper, resp.Status)
		return false, nil
	}
}
