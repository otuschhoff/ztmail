package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"gopkg.in/jcmturner/gokrb5.v7/asn1tools"
	"gopkg.in/jcmturner/gokrb5.v7/crypto"
	"gopkg.in/jcmturner/gokrb5.v7/gssapi"
	"gopkg.in/jcmturner/gokrb5.v7/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/messages"
	"gopkg.in/jcmturner/gokrb5.v7/types"
)

func testKey() types.EncryptionKey {
	return types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x42}, 16)}
}

func acceptorToken(t *testing.T, key types.EncryptionKey, flag byte, sequence uint64, payload []byte, rotation uint16) []byte {
	t.Helper()
	token := gssapi.WrapToken{Flags: 1 | flag, EC: 12, SndSeqNum: sequence, Payload: payload}
	if err := token.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatal(err)
	}
	data, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if rotation != 0 {
		body := append([]byte(nil), data[16:]...)
		r := int(rotation) % len(body)
		copy(data[16:], append(body[len(body)-r:], body[:len(body)-r]...))
		binary.BigEndian.PutUint16(data[6:8], rotation)
	}
	return data
}

func TestKerberosWrapExchange(t *testing.T) {
	for _, subkey := range []bool{false, true} {
		for _, rotation := range []uint16{0, 12, 28, 65535} {
			c := &kerberosContext{key: testKey(), established: true, sendSequence: 53, receiveSequence: 71}
			key, flag := c.key, byte(0)
			if subkey {
				c.subkey = types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x33}, 16)}
				key, flag = c.subkey, 4
			}
			offer := []byte{7, 0, 16, 0}
			input := acceptorToken(t, key, flag, 71, offer, rotation)
			before := append([]byte(nil), input...)
			plain, err := c.Unwrap(input)
			if err != nil || !bytes.Equal(plain, offer) {
				t.Fatalf("Unwrap: plain=%x err=%v", plain, err)
			}
			if !bytes.Equal(input, before) {
				t.Fatal("Unwrap modified caller's token")
			}
			if _, err := c.Unwrap(input); err == nil {
				t.Fatal("replayed server token accepted")
			}
			wrapped, err := c.Wrap([]byte{1, 0, 0, 0})
			if err != nil {
				t.Fatal(err)
			}
			var token gssapi.WrapToken
			if err := token.Unmarshal(wrapped, false); err != nil {
				t.Fatal(err)
			}
			if token.Flags != flag || token.SndSeqNum != 53 || !bytes.Equal(token.Payload, []byte{1, 0, 0, 0}) {
				t.Fatalf("invalid selection token: %+v", token)
			}
			if ok, err := token.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL); !ok || err != nil {
				t.Fatalf("selection checksum: %v", err)
			}
		}
	}
}

func TestKerberosRejectInvalidWrap(t *testing.T) {
	valid := acceptorToken(t, testKey(), 0, 0, []byte{1, 0, 0, 0}, 0)
	for _, kind := range []string{"checksum", "direction", "sealed", "subkey", "sequence", "short"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			switch kind {
			case "checksum":
				data[len(data)-1] ^= 1
			case "direction":
				data[2] = 0
			case "sealed":
				data[2] |= 2
			case "subkey":
				data[2] |= 4
			case "sequence":
				binary.BigEndian.PutUint64(data[8:16], 1)
			case "short":
				data = data[:10]
			}
			c := &kerberosContext{key: testKey(), established: true}
			if _, err := c.Unwrap(data); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	c := &kerberosContext{}
	if _, err := c.Unwrap(valid); err == nil {
		t.Fatal("unestablished unwrap accepted")
	}
	if _, err := c.Wrap([]byte{1}); err == nil {
		t.Fatal("unestablished wrap accepted")
	}
}

func apReply(t *testing.T, stamp time.Time, usec int, key types.EncryptionKey) []byte {
	t.Helper()
	part, err := asn1.Marshal(messages.EncAPRepPart{CTime: stamp, Cusec: usec, SequenceNumber: 71})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.GetEncryptedData(asn1tools.AddASNAppTag(part, 27), key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := asn1.Marshal(messages.APRep{PVNO: 5, MsgType: 15, EncPart: encrypted})
	if err != nil {
		t.Fatal(err)
	}
	oid, err := asn1.Marshal(gssapi.OID(gssapi.OIDKRB5))
	if err != nil {
		t.Fatal(err)
	}
	inner := append(oid, 2, 0)
	inner = append(inner, asn1tools.AddASNAppTag(reply, 15)...)
	return asn1tools.AddASNAppTag(inner, 0)
}

func TestKerberosMutualAuthentication(t *testing.T) {
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, mismatch := range []bool{false, true} {
		c := &kerberosContext{key: testKey(), authTime: stamp, authUsec: 123}
		usec := 123
		if mismatch {
			usec++
		}
		_, done, err := c.Step(apReply(t, stamp, usec, testKey()))
		if mismatch && err == nil {
			t.Fatal("AP-REP with mismatched timestamp accepted")
		}
		if !mismatch && (err != nil || !done || c.receiveSequence != 71) {
			t.Fatalf("valid AP-REP failed: done=%v err=%v", done, err)
		}
	}
	c := &kerberosContext{key: testKey()}
	if _, _, err := c.Step([]byte("not an AP-REP")); err == nil {
		t.Fatal("invalid AP-REP accepted")
	}
}

func TestCachePath(t *testing.T) {
	for _, tt := range []struct {
		input, want string
		fail        bool
	}{
		{"FILE:/tmp/cache", "/tmp/cache", false},
		{"/tmp/cache", "/tmp/cache", false},
		{`C:\cache`, `C:\cache`, false},
		{"DIR:/tmp/caches", "", true},
		{"KEYRING:persistent:1000", "", true},
		{"FILE:", "", true},
	} {
		got, err := cachePath(tt.input)
		if got != tt.want || (err != nil) != tt.fail {
			t.Errorf("%q: %q %v", tt.input, got, err)
		}
	}
}

func TestKerberosConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte("[libdefaults]\n default_realm = OLD.REALM\n dns_lookup_kdc = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := options{krbConfig: path, domain: "example.com", realm: "EXAMPLE.COM"}
	cfg, err := kerberosConfig(o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LibDefaults.DefaultRealm != o.realm || cfg.DomainRealm[".example.com"] != o.realm || !cfg.LibDefaults.DNSLookupKDC {
		t.Fatalf("config not set for AD realm: %+v", cfg)
	}
	o.krbConfig = path + "-missing"
	if _, err := kerberosConfig(o); err == nil {
		t.Fatal("explicit missing config silently ignored")
	}
}

func TestMissingDefaultKerberosConfigUsesDNS(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.conf")
	cfg, err := loadKerberosConfig(missing, true)
	if err != nil || !cfg.LibDefaults.DNSLookupKDC {
		t.Fatalf("missing default config must enable DNS KDC discovery: cfg=%v err=%v", cfg, err)
	}
	if _, err := loadKerberosConfig(missing, false); err == nil {
		t.Fatal("explicit missing config accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.conf")
	if err := os.WriteFile(bad, []byte("[libdefaults]\n dns_lookup_kdc = definitely-not-a-boolean\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKerberosConfig(bad, true); err == nil {
		t.Fatal("malformed default config silently replaced")
	}
}

func TestKeytabPrincipal(t *testing.T) {
	// A version-2 keytab with a single AES key; no real credentials.
	var entry bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&entry, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	str := func(s string) { put(uint16(len(s))); entry.WriteString(s) }
	put(uint16(1))
	str("EXAMPLE.COM")
	str("mailer")
	put(uint32(1))
	put(uint32(1))
	put(byte(1))
	put(uint16(17))
	put(uint16(16))
	entry.Write(testKey().KeyValue)
	var wire bytes.Buffer
	wire.Write([]byte{5, 2})
	if err := binary.Write(&wire, binary.BigEndian, int32(entry.Len())); err != nil {
		t.Fatal(err)
	}
	wire.Write(entry.Bytes())
	kt := keytab.New()
	if err := kt.Unmarshal(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	for _, request := range []string{"", "mailer", "mailer@EXAMPLE.COM"} {
		name, err := keytabPrincipal(kt, request, "EXAMPLE.COM")
		if err != nil || name != "mailer" {
			t.Fatalf("principal=%q err=%v", name, err)
		}
	}
	for _, request := range []string{"missing", "mailer@OTHER.COM", "@EXAMPLE.COM"} {
		if _, err := keytabPrincipal(kt, request, "EXAMPLE.COM"); err == nil {
			t.Fatalf("invalid principal %q accepted", request)
		}
	}
	if _, err := keytabPrincipal(kt, "", "OTHER.COM"); err == nil {
		t.Fatal("empty realm selection accepted")
	}
	kt.Entries = append(kt.Entries, kt.Entries[0])
	kt.Entries[1].Principal.Components = []string{"other"}
	if reflect.DeepEqual(kt.Entries[0].Principal.Components, kt.Entries[1].Principal.Components) {
		t.Fatal("test setup shares principal")
	}
	if _, err := keytabPrincipal(kt, "", "EXAMPLE.COM"); err == nil {
		t.Fatal("ambiguous keytab accepted")
	}
}
