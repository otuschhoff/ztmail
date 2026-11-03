package mail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/kerberos"
	adldap "github.com/otuschhoff/adbind/ad/ldap"
)

// These public-SDK fixtures use toy SASL contexts, not real Kerberos credentials.
type ldapRaceFixture struct {
	t              *testing.T
	owner          *adclient.Client
	locator        *discovery.Locator
	identity       kerberos.Identity
	tls            *tls.Config
	validity       context.Context
	dials          atomic.Int32
	roots          atomic.Int32
	searches       atomic.Int32
	acquired       atomic.Int32
	released       atomic.Int32
	deleted        atomic.Int32
	hold           atomic.Bool
	entered        chan int
	release        chan struct{}
	winner         chan struct{}
	stopOnce       sync.Once
	workers        sync.WaitGroup
	winnerRows     int
	invalidDN      bool
	mailboxMissing bool
	objectClasses  []string
}

func (f *ldapRaceFixture) LookupSRV(ctx context.Context, name string) (string, []*net.SRV, error) {
	records := make([]*net.SRV, 8)
	for i := range records {
		records[i] = &net.SRV{Target: fmt.Sprintf("dc%d.example.test.", i+1), Port: 1389}
	}
	return name, records, ctx.Err()
}

func (f *ldapRaceFixture) LookupHost(ctx context.Context, name string) ([]string, error) {
	for i := range 8 {
		if strings.TrimSuffix(name, ".") == fmt.Sprintf("dc%d.example.test", i+1) {
			return []string{fmt.Sprintf("192.0.2.%d", i+1)}, ctx.Err()
		}
	}
	return nil, fmt.Errorf("unexpected LDAP hostname %q", name)
}

func (f *ldapRaceFixture) Acquire(ctx context.Context) (adclient.AuthenticationLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.acquired.Add(1)
	return &ldapRaceLease{fixture: f}, nil
}

type ldapRaceLease struct {
	fixture  *ldapRaceFixture
	released atomic.Bool
}

func (l *ldapRaceLease) Identity() (adclient.AuthenticationIdentity, error) {
	return adclient.AuthenticationIdentity{
		Principal: l.fixture.identity.Principal, Realm: l.fixture.identity.Realm, Generation: 1,
	}, nil
}
func (l *ldapRaceLease) Context() context.Context { return l.fixture.validity }
func (l *ldapRaceLease) Release() {
	if !l.released.CompareAndSwap(false, true) {
		l.fixture.t.Error("LDAP operation grant released twice")
	}
	l.fixture.released.Add(1)
}
func (l *ldapRaceLease) NewSecurityContext(ctx context.Context, spn string, state *tls.ConnectionState) (adldap.SecurityContext, error) {
	host := strings.TrimSuffix(strings.TrimPrefix(spn, "ldap/"), "@EXAMPLE.TEST")
	if state == nil || !state.HandshakeComplete || state.ServerName != host || len(state.VerifiedChains) == 0 {
		return nil, errors.New("LDAP context did not receive verified TLS state")
	}
	return &ldapRaceContext{fixture: l.fixture}, ctx.Err()
}

type ldapRaceContext struct {
	adldap.SecurityContext
	fixture *ldapRaceFixture
	step    int
	deleted atomic.Bool
}

func (c *ldapRaceContext) InitSecContextWithOptions(_ string, input []byte, options []int) ([]byte, bool, error) {
	if !slices.Contains(options, 2) {
		return nil, false, errors.New("LDAP context omitted mutual authentication")
	}
	c.step++
	if c.step == 1 && len(input) == 0 {
		return []byte("init"), true, nil
	}
	if c.step == 2 && string(input) == "mutual" {
		return nil, false, nil
	}
	return nil, false, errors.New("unexpected LDAP context continuation")
}
func (c *ldapRaceContext) InitSecContext(spn string, input []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(spn, input, []int{2})
}
func (c *ldapRaceContext) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if string(input) != "layers" || authzid != "" {
		return nil, errors.New("unexpected LDAP SASL offer")
	}
	return []byte("selected"), nil
}
func (c *ldapRaceContext) ConfirmBind() error { return nil }
func (c *ldapRaceContext) DeleteSecContext() error {
	if !c.deleted.CompareAndSwap(false, true) {
		return errors.New("LDAP context deleted twice")
	}
	c.fixture.deleted.Add(1)
	return nil
}

func ldapEnvelope(id int64, operation *ber.Packet) *ber.Packet {
	message := ber.NewSequence("")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	message.AppendChild(operation)
	return message
}

func ldapReply(id int64, tag ber.Tag, code int64, token string) *ber.Packet {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	if token != "" {
		result.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, token, ""))
	}
	return ldapEnvelope(id, result)
}

func ldapAttributeEntry(id int64, dn, name string, values ...string) []byte {
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
	attributes := ber.NewSequence("")
	attribute := ber.NewSequence("")
	attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
	for _, value := range values {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
	}
	attribute.AppendChild(set)
	attributes.AppendChild(attribute)
	entry.AppendChild(attributes)
	return ldapEnvelope(id, entry).Bytes()
}

func (f *ldapRaceFixture) serve(raw net.Conn, index int) {
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			f.t.Error(err)
		}
		return
	}
	request, err := ber.ReadPacket(raw)
	if err != nil || request.Children[1].Tag != 23 {
		return
	}
	if _, err := raw.Write(ldapReply(request.Children[0].Value.(int64), 24, 0, "").Bytes()); err != nil {
		return
	}
	stream := tls.Server(raw, f.tls)
	if err := stream.Handshake(); err != nil {
		return
	}
	for i, token := range []string{"mutual", "layers", ""} {
		request, err := ber.ReadPacket(stream)
		if err != nil {
			return
		}
		if request.Children[1].Tag != 0 {
			f.t.Error("expected LDAP SASL bind")
			return
		}
		code := int64(14)
		if i == 2 {
			code = 0
		}
		if _, err := stream.Write(ldapReply(request.Children[0].Value.(int64), 1, code, token).Bytes()); err != nil {
			return
		}
	}
	base := fmt.Sprintf("DC=lane%d,DC=test", index)
	if f.invalidDN {
		base = "not a DN"
	}
	for {
		request, err := ber.ReadPacket(stream)
		if err != nil || request.Children[1].Tag == 2 {
			return
		}
		query := request.Children[1]
		if query.Tag != 3 {
			f.t.Error("expected LDAP search")
			return
		}
		id := request.Children[0].Value.(int64)
		root := query.Children[0].Data.Len() == 0
		scoped := 0
		if len(request.Children) == 3 {
			for _, encoded := range request.Children[2].Children {
				control, err := ldap.DecodeControl(encoded)
				if err != nil {
					f.t.Error(err)
					return
				}
				if control.GetControlType() == "1.2.840.113556.1.4.1339" {
					scoped++
					value, ok := control.(*ldap.ControlString)
					if !ok || !value.Criticality || value.ControlValue != "" {
						f.t.Error("LDAP naming-context protection changed")
					}
				}
				if root && control.GetControlType() == ldap.ControlTypePaging {
					f.t.Error("RootDSE requested paging")
				}
			}
		}
		var body []byte
		if root {
			f.roots.Add(1)
			if scoped != 0 || query.Children[1].Value != int64(ldap.ScopeBaseObject) {
				f.t.Error("RootDSE was scoped")
			}
			body = ldapAttributeEntry(id, "", "defaultNamingContext", base)
		} else {
			f.searches.Add(1)
			filter, err := ldap.DecompileFilter(query.Children[6])
			if err != nil {
				f.t.Error(err)
				return
			}
			name := strings.Split(f.identity.Principal, "@")[0]
			attribute := "sAMAccountName"
			if strings.Contains(name, "/") {
				attribute = "servicePrincipalName"
			}
			expected := "(&(objectClass=user)(|(userPrincipalName=" + ldap.EscapeFilter(f.identity.Principal) +
				")(" + attribute + "=" + ldap.EscapeFilter(name) + ")))"
			var attributes []string
			for _, attribute := range query.Children[7].Children {
				attributes = append(attributes, attribute.Data.String())
			}
			if scoped != 1 || query.Children[0].Data.String() != base || filter != expected ||
				query.Children[3].Value != int64(2) || !reflect.DeepEqual(attributes, []string{"mail", "proxyAddresses", "objectClass"}) {
				f.t.Errorf("LDAP lookup escaped its candidate/policy: base=%q filter=%q scoped=%d attributes=%v",
					query.Children[0].Data.String(), filter, scoped, attributes)
			}
			f.entered <- index
			if f.hold.Load() {
				if index == 0 {
					select {
					case <-f.winner:
					case <-f.release:
					}
				} else {
					<-f.release
				}
			}
			count := 1
			if index == 0 {
				count = f.winnerRows
			}
			for row := range count {
				dn := fmt.Sprintf("CN=User%d,%s", row, base)
				if f.mailboxMissing {
					body = append(body, ldapAttributeEntry(id, dn, "objectClass", f.objectClasses...)...)
				} else {
					body = append(body, ldapAttributeEntry(id, dn, "proxyAddresses", "SMTP:alice@example.test")...)
				}
			}
		}
		done := ldapReply(id, 5, 0, "")
		if !root {
			controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
			controls.AppendChild(ldap.NewControlPaging(0).Encode())
			done.AppendChild(controls)
		}
		body = append(body, done.Bytes()...)
		if _, err := stream.Write(body); err != nil {
			return
		}
	}
}

func newLDAPRaceFixture(t *testing.T, principal string) *ldapRaceFixture {
	t.Helper()
	f := &ldapRaceFixture{t: t, identity: kerberos.Identity{Principal: principal, Realm: "EXAMPLE.TEST"},
		entered: make(chan int, 16), release: make(chan struct{}), winner: make(chan struct{}), winnerRows: 1}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LDAP fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for i := range 8 {
		template.DNSNames = append(template.DNSNames, fmt.Sprintf("dc%d.example.test", i+1))
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := adclient.NewTrustFromPEM(adclient.TrustPolicy{}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
	if err != nil {
		t.Fatal(err)
	}
	f.tls = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}}
	validity, cancel := context.WithCancel(context.Background())
	f.validity = validity
	f.locator, err = discovery.New(discovery.Options{Domain: "example.test", Resolver: f})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f.owner, err = adclient.New(adclient.Options{Locator: f.locator, Authentication: f, Realm: "EXAMPLE.TEST",
		Trust: trust, Protection: "tls", DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid fixture address %q: %w", address, err)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if network != "tcp" || target.Port() != 1389 {
				return nil, fmt.Errorf("unexpected fixture dial %s %q", network, address)
			}
			index, err := strconv.Atoi(strings.TrimPrefix(target.Addr().String(), "192.0.2."))
			if err != nil || index < 1 || index > 8 {
				return nil, fmt.Errorf("unexpected fixture target %q", address)
			}
			f.dials.Add(1)
			left, right := net.Pipe()
			f.workers.Add(1)
			go func() { defer f.workers.Done(); f.serve(right, index-1) }()
			return left, nil
		}})
	if err != nil {
		cancel()
		if closeErr := f.locator.Close(context.Background()); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.stopOnce.Do(func() { close(f.release) })
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := f.owner.Close(cleanup); err != nil {
			t.Error(err)
		}
		if err := f.locator.Close(cleanup); err != nil {
			t.Error(err)
		}
		cancel()
		f.workers.Wait()
	})
	return f
}

func TestCanonicalLDAPRaceCompleteEightDCLookup(t *testing.T) {
	for _, principal := range []string{"Alice@Example.TEST", "smtp/relay@Example.TEST"} {
		f := newLDAPRaceFixture(t, principal)
		f.hold.Store(true)
		type lookupOutcome struct {
			address string
			err     error
		}
		done := make(chan lookupOutcome, 1)
		go func() {
			address, err := LookupCanonicalMail(t.Context(), f.owner, f.identity, 8)
			done <- lookupOutcome{address.Address, err}
		}()
		var seen [8]bool
		for range 8 {
			select {
			case index := <-f.entered:
				if seen[index] {
					t.Fatalf("DC candidate %d was raced more than once", index)
				}
				seen[index] = true
			case result := <-done:
				t.Fatalf("race ended before eight complete candidate lookups: %+v", result)
			case <-time.After(5 * time.Second):
				t.Fatal("eight LDAP candidates did not start immediately")
			}
		}
		close(f.winner)
		var result lookupOutcome
		select {
		case result = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("successful election waited for blocked peer responses")
		}
		if result.err != nil || result.address != "alice@example.test" ||
			f.dials.Load() != 8 || f.roots.Load() != 8 || f.searches.Load() != 8 ||
			f.acquired.Load() != 1 || f.released.Load() != 1 || f.deleted.Load() != 8 {
			t.Fatalf("LDAP racing or single-use ownership mismatch: %+v dials=%d roots=%d searches=%d grants=%d/%d contexts=%d",
				result, f.dials.Load(), f.roots.Load(), f.searches.Load(), f.acquired.Load(), f.released.Load(), f.deleted.Load())
		}
		if f.locator.Inventory().Closed || f.validity.Err() != nil {
			t.Fatal("mail lookup closed a borrowed owner")
		}
	}
}

func TestCanonicalLDAPRaceFirstCompleteNegativeWins(t *testing.T) {
	for _, tt := range []struct {
		name string
		rows int
		want error
	}{
		{"empty", 0, directory.ErrNotFound},
		{"ambiguous", 2, directory.ErrAmbiguous},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newLDAPRaceFixture(t, "alice@EXAMPLE.TEST")
			f.winnerRows = tt.rows
			f.hold.Store(true)
			done := make(chan error, 1)
			go func() {
				address, err := LookupCanonicalMail(t.Context(), f.owner, f.identity, 8)
				if address != (CanonicalMailbox{}) {
					t.Errorf("negative election returned a mailbox: %+v", address)
				}
				done <- err
			}()
			for range 8 {
				select {
				case <-f.entered:
				case err := <-done:
					t.Fatalf("race ended before candidates reached their user lookup: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("LDAP candidates did not enter")
				}
			}
			close(f.winner)
			select {
			case err := <-done:
				if !errors.Is(err, tt.want) || f.deleted.Load() != 8 || f.released.Load() != 1 {
					t.Fatalf("negative election or loser cleanup failed: %v contexts=%d grants=%d",
						err, f.deleted.Load(), f.released.Load())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("race waited for favorable replicas or blocked peer responses")
			}
			if f.locator.Inventory().Closed || f.validity.Err() != nil {
				t.Fatal("negative lookup closed a borrowed owner")
			}
		})
	}
}

func TestCanonicalLDAPRaceCancellationPreservesOwner(t *testing.T) {
	f := newLDAPRaceFixture(t, "alice@EXAMPLE.TEST")
	f.hold.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		address, err := LookupCanonicalMail(ctx, f.owner, f.identity, 8)
		if address != (CanonicalMailbox{}) {
			t.Errorf("canceled race returned a mailbox: %+v", address)
		}
		done <- err
	}()
	for range 8 {
		select {
		case <-f.entered:
		case err := <-done:
			t.Fatalf("race ended before caller cancellation: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("LDAP candidates did not enter")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || f.deleted.Load() != 8 || f.released.Load() != 1 {
			t.Fatalf("cancellation did not drain SDK work: %v contexts=%d grants=%d",
				err, f.deleted.Load(), f.released.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled race waited for peer responses")
	}
	f.stopOnce.Do(func() { close(f.release) })
	f.workers.Wait()
	f.hold.Store(false)
	address, err := LookupCanonicalMail(t.Context(), f.owner, f.identity, 0)
	if err != nil || address.Address != "alice@example.test" || f.validity.Err() != nil || f.locator.Inventory().Closed {
		t.Fatalf("cancellation invalidated the borrowed owner: %+v %v", address, err)
	}
}

func TestCanonicalLDAPRaceInvalidInputsAvoidIO(t *testing.T) {
	for _, tt := range []struct {
		principal  string
		candidates int
	}{
		{"alice@OTHER.TEST", 8},
		{"alice @EXAMPLE.TEST", 8},
		{"alice@EXAMPLE.TEST", -1},
		{"alice@EXAMPLE.TEST", 9},
	} {
		f := newLDAPRaceFixture(t, tt.principal)
		address, err := LookupCanonicalMail(t.Context(), f.owner, f.identity, tt.candidates)
		if err == nil || address != (CanonicalMailbox{}) || f.dials.Load() != 0 || f.acquired.Load() != 0 {
			t.Fatalf("invalid lookup performed I/O: %+v mailbox=%+v err=%v dials=%d grants=%d",
				tt, address, err, f.dials.Load(), f.acquired.Load())
		}
	}
}

func TestCanonicalLDAPHostMailboxMissingInOrdinaryAndRacedReads(t *testing.T) {
	for _, candidates := range []int{0, 8} {
		for _, computer := range []bool{false, true} {
			t.Run(fmt.Sprintf("candidates-%d/computer-%t", candidates, computer), func(t *testing.T) {
				f := newLDAPRaceFixture(t, "SNEU1-AL04$@EXAMPLE.TEST")
				f.mailboxMissing = true
				f.objectClasses = []string{"top", "person", "user"}
				if computer {
					f.objectClasses = append(f.objectClasses, "computer")
				}
				result, err := LookupCanonicalMail(t.Context(), f.owner, f.identity, candidates)
				if computer {
					if err != nil || result != (CanonicalMailbox{HostWithoutMail: true}) {
						t.Fatalf("host mailbox absence failed the complete lookup: %+v %v", result, err)
					}
				} else if !errors.Is(err, directory.ErrMissingAttribute) || result != (CanonicalMailbox{}) {
					t.Fatalf("a dollar-suffixed user bypassed required mail: %+v %v", result, err)
				}
				if f.searches.Load() == 0 || f.locator.Inventory().Closed || f.validity.Err() != nil ||
					f.acquired.Load() != f.released.Load() {
					t.Fatalf("lookup was skipped or changed owner/grant lifetime: searches=%d grants=%d/%d",
						f.searches.Load(), f.acquired.Load(), f.released.Load())
				}
			})
		}
	}
}

func TestCanonicalLDAPOrdinaryReadAndInvalidRoot(t *testing.T) {
	for _, tt := range []struct {
		invalid    bool
		candidates int
	}{{false, 0}, {true, 0}, {true, 8}} {
		f := newLDAPRaceFixture(t, "alice@EXAMPLE.TEST")
		f.invalidDN = tt.invalid
		address, err := LookupCanonicalMail(t.Context(), f.owner, f.identity, tt.candidates)
		if tt.invalid {
			if err == nil || f.searches.Load() != 0 {
				t.Fatalf("invalid RootDSE reached the user search: %+v %v", address, err)
			}
		} else if err != nil || address.Address != "alice@example.test" || f.dials.Load() != 1 {
			t.Fatalf("ordinary LDAP selection changed: %+v %v dials=%d", address, err, f.dials.Load())
		}
		if f.locator.Inventory().Closed || f.validity.Err() != nil {
			t.Fatal("ordinary lookup closed its owner")
		}
	}
}
