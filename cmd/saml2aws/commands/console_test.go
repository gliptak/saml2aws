package commands

import (
	"bytes"
	"crypto/tls"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"net/http"
	"net/http/httptest"
	"strings"

	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/prompter"
)

func TestConsole(t *testing.T) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	svr := httptest.NewTLSServer(http.HandlerFunc(nil))
	assertion, err := ioutil.ReadFile("example/assertion.xml")
	assert.Nil(t, err)
	assertion = bytes.Replace(assertion, []byte("https://signin.aws.amazon.com"), []byte(svr.URL), 1)
	assertion_s := b64.StdEncoding.EncodeToString(assertion)
	svr.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.String(), "/adfs/ls/IdpInitiatedSignOn.aspx") {
			_, err := w.Write([]byte(fmt.Sprintf(`
			     <input type="hidden" name="SAMLResponse" value="%s">
				`, assertion_s)))
			assert.Nil(t, err)
		} else 		if strings.HasPrefix(r.URL.String(), "/saml") {
			resp, err := ioutil.ReadFile("example/saml.html")
			assert.Nil(t, err)
			_, err = w.Write(resp)
			assert.Nil(t, err)
		} else {
			t.Fatalf("unexpected %v", r)
		}
	})
	defer svr.Close()

	bytesRead, err := ioutil.ReadFile("example/saml2aws.ini")
	assert.Nil(t, err)
	bytesRead = bytes.Replace(bytesRead, []byte("https://id.whatever.com"), []byte(svr.URL), 1)
	err = ioutil.WriteFile("example/saml2aws.tmp", bytesRead, 0644)
	assert.Nil(t, err)
	defer os.Remove("example/saml2aws.tmp")

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("String", "Username", "abc@whatever.com").Return("abc@whatever.com")
	pr.Mock.On("Password", "Password").Return("password1")
	pr.Mock.On("ChooseWithDefault",
		"Please choose the role",
		"Account: 000000000002 / Production",
		[]string{"Account: 000000000002 / Production", "Account: account-alias (000000000001) / Development", "Account: account-alias (000000000001) / Production"}).Return("Account: 000000000002 / Production", nil)

	consoleFlags := new(flags.ConsoleFlags)
	consoleFlags.LoginExecFlags = new(flags.LoginExecFlags)
	consoleFlags.LoginExecFlags.CommonFlags = new(flags.CommonFlags)
	consoleFlags.LoginExecFlags.CommonFlags.ConfigFile = "example/saml2aws.tmp"
	consoleFlags.LoginExecFlags.CommonFlags.IdpAccount = "test123"
	err = Console(consoleFlags)
    assert.Nil(t, err)
}