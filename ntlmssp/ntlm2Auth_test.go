package ntlmssp

import (
	"testing"
	"net/http/httptest"
	"net/http"
	"log"
	"io/ioutil"
	"bytes"
	"strings"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
)


func TestChallengeRequested(t *testing.T) {
	log.SetOutput(ioutil.Discard)

	var (
		output string
		// Exactly what CURL does
		expected = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAMAA="
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		output = r.Header.Get("Authorization")
	})

	s:=httptest.NewServer(handler)
	defer s.Close()

	auth := &ntlm2Authenticator{ }
	auth.execChallengeRequest(s.URL, DefaultClient)

	if output != expected {
		t.Errorf("Invalid negotiate message %s: expected %s", output, expected)
	}

}


func TestChallengeReceived(t *testing.T) {
	log.SetOutput(ioutil.Discard)

	var (
		msg2 = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAMAA="
		expected,_ = decodeBase64(strings.Replace(msg2,ntlmHeaderValuePrefix,"",1) )
	)


	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(authenticateHeaderKey,msg2)
	})

	s:=httptest.NewServer(handler)
	defer s.Close()

	auth := &ntlm2Authenticator{ }
	output, _ := auth.execChallengeRequest(s.URL, DefaultClient)

	if bytes.Equal(output, expected) == false {
		t.Errorf("Wrong challenge %s: expected %s", output, expected)
	}

}



func TestChallengeAnswered(t *testing.T){

	var (
		user = "user"
		password = "password"
		output string
		err error
	)



	serverSess, _ := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	serverSess.SetUserInfo(user, password, "")
	challenge, _ := serverSess.GenerateChallengeMessage()
	challMsg,_ := ntlm.ParseChallengeMessage(challenge.Bytes())

	clientSess, _ := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	clientSess.SetUserInfo(user,password,"")
	clientSess.ProcessChallengeMessage(challMsg)
	authMsg,_ := clientSess.GenerateAuthenticateMessage()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		output = r.Header.Get("Authorization")
		bytes ,_ := decodeBase64(strings.Replace(output, ntlmHeaderValuePrefix,"",1))
		_,err = ntlm.ParseAuthenticateMessage (bytes,2)
	})

	//log.Println(authMsg..String())
	s:=httptest.NewServer(handler)
	defer s.Close()
	//
	auth := &ntlm2Authenticator{ }
	auth.execAuthRequest(s.URL, authMsg, DefaultClient)

	if strings.Contains(output,ntlmHeaderValuePrefix) == false {
		t.Errorf("Incorrect Auth header %s", output)
	}

	if err != nil{
		t.Errorf("Error parsing authenticate message: %s", err)
	}

}