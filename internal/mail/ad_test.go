package mail

import (
	"github.com/otuschhoff/adbind/ad/kerberos"
	"reflect"
	"testing"
)

type fakeADContext struct {
	kerberos.SecurityContext
	target  string
	options []int
	more    bool
	fail    error
	offer   []byte
	authzid string
	closed  bool
}

func (f *fakeADContext) InitSecContextWithOptions(target string, input []byte, options []int) ([]byte, bool, error) {
	f.target, f.options = target, options
	return []byte("request"), f.more, f.fail
}
func (f *fakeADContext) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	f.target = target
	return []byte("reply"), f.more, f.fail
}
func (f *fakeADContext) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	f.offer, f.authzid = input, authzid
	return []byte("selection"), f.fail
}
func (f *fakeADContext) DeleteSecContext() error { f.closed = true; return f.fail }

func TestADSecurityContextDelegatesToSDK(t *testing.T) {
	fake := &fakeADContext{more: true}
	c := &adSecurityContext{context: fake, target: "smtp/mailgw.example.com"}
	token, err := c.Start()
	if err != nil || string(token) != "request" || fake.target != c.target || !reflect.DeepEqual(fake.options, []int{2}) {
		t.Fatalf("Start=%q %v target=%s options=%v", token, err, fake.target, fake.options)
	}
	fake.more = false
	if _, done, err := c.Step([]byte("AP-REP")); err != nil || !done {
		t.Fatalf("Step=%v %v", done, err)
	}
	selection, err := c.Negotiate([]byte("offer"))
	if err != nil || string(selection) != "selection" || string(fake.offer) != "offer" || fake.authzid != "" {
		t.Fatalf("Negotiate=%q %v", selection, err)
	}
	if err := c.Close(); err != nil || !fake.closed {
		t.Fatalf("Close=%v closed=%v", err, fake.closed)
	}
	if _, err := c.Start(); err == nil {
		t.Fatal("premature context completion accepted")
	}
}
