package mail

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"
)

type AuthMode string

const (
	AuthGSSAPI       AuthMode = "gssapi"
	AuthMTLS         AuthMode = "mtls"
	AuthMTLSExternal AuthMode = "mtls-external"
)

type RootMode string

const (
	RootsSystem  RootMode = "system"
	RootsAppend  RootMode = "append"
	RootsReplace RootMode = "replace"
)

type CASelectorKind string

const (
	CACertificateSHA256 CASelectorKind = "certificate-sha256"
	CASPKISHA256        CASelectorKind = "spki-sha256"
)

type CASelector struct {
	Kind   CASelectorKind
	Digest [sha256.Size]byte
}

type ServerTrust struct {
	Mode                            RootMode
	Certificates                    [][]byte
	Allow, Deny                     []CASelector
	ExpiredServerCertificateGrace   time.Duration
	InsecureAllowUnverifiableIssuer bool
}

var ErrTLSFeatureUnavailable = errors.New("TLS feature unavailable on this platform")

func ParseCASelector(kind CASelectorKind, value string) (CASelector, error) {
	if kind != CACertificateSHA256 && kind != CASPKISHA256 {
		return CASelector{}, errors.New("invalid CA selector kind")
	}
	normalized := strings.ReplaceAll(value, ":", "")
	raw, err := hex.DecodeString(normalized)
	if err != nil || len(raw) != sha256.Size {
		return CASelector{}, errors.New("CA selector requires a 32-byte SHA-256 digest in hexadecimal")
	}
	var digest [sha256.Size]byte
	copy(digest[:], raw)
	return CASelector{Kind: kind, Digest: digest}, nil
}

func cloneServerTrust(o ServerTrust) (ServerTrust, error) {
	if o.Mode == "" {
		o.Mode = RootsSystem
		if len(o.Certificates) > 0 {
			o.Mode = RootsAppend
		}
	}
	switch o.Mode {
	case RootsSystem:
		if len(o.Certificates) != 0 {
			return ServerTrust{}, errors.New("system root mode cannot include custom CA certificates")
		}
	case RootsAppend, RootsReplace:
		if len(o.Certificates) == 0 {
			return ServerTrust{}, errors.New("append/replace root mode requires CA certificates")
		}
	default:
		return ServerTrust{}, errors.New("TLS root mode must be system, append, or replace")
	}
	if o.ExpiredServerCertificateGrace < 0 {
		return ServerTrust{}, errors.New("server certificate expiry grace cannot be negative")
	}
	if o.ExpiredServerCertificateGrace > 0 && o.Mode != RootsReplace &&
		(runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios") {
		return ServerTrust{}, fmt.Errorf("%w: expiry grace with native system/append roots; use PEM replace mode", ErrTLSFeatureUnavailable)
	}
	original := o.Certificates
	o.Certificates = make([][]byte, len(original))
	for i, der := range original {
		o.Certificates[i] = bytes.Clone(der)
		cert, err := x509.ParseCertificate(o.Certificates[i])
		if err != nil {
			return ServerTrust{}, fmt.Errorf("TLS root certificate %d: %w", i+1, err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ServerTrust{}, fmt.Errorf("TLS root certificate %d is not a signing CA", i+1)
		}
	}
	o.Allow, o.Deny = slices.Clone(o.Allow), slices.Clone(o.Deny)
	for _, selector := range append(slices.Clone(o.Allow), o.Deny...) {
		if selector.Kind != CACertificateSHA256 && selector.Kind != CASPKISHA256 {
			return ServerTrust{}, errors.New("invalid CA selector kind")
		}
	}
	return o, nil
}

func serverRoots(o ServerTrust) (*x509.CertPool, error) {
	var roots *x509.CertPool
	if o.Mode == RootsReplace {
		roots = x509.NewCertPool()
	} else {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("system TLS roots: %w", err)
		}
		if roots == nil {
			return nil, errors.New("system TLS roots unavailable")
		}
	}
	for _, der := range o.Certificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("TLS CA certificate: %w", err)
		}
		roots.AddCert(cert)
	}
	return roots, nil
}

func selectorMatches(selector CASelector, cert *x509.Certificate) bool {
	raw := cert.Raw
	if selector.Kind == CASPKISHA256 {
		raw = cert.RawSubjectPublicKeyInfo
	}
	return sha256.Sum256(raw) == selector.Digest
}

func acceptableServerChain(chains [][]*x509.Certificate, policy ServerTrust, now time.Time) ([]*x509.Certificate, error) {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		anchor := chain[len(chain)-1]
		if len(policy.Allow) > 0 && !slices.ContainsFunc(policy.Allow, func(s CASelector) bool { return selectorMatches(s, anchor) }) {
			continue
		}
		denied := false
		for i, cert := range chain {
			if i != 0 || cert.IsCA || len(chain) == 1 {
				if now.Before(cert.NotBefore) || now.After(cert.NotAfter) ||
					slices.ContainsFunc(policy.Deny, func(s CASelector) bool { return selectorMatches(s, cert) }) {
					denied = true
					break
				}
			}
		}
		if !denied {
			return chain, nil
		}
	}
	return nil, errors.New("no server certificate chain satisfies CA allow/deny and CA validity policy")
}

type serverVerification struct {
	chain      []*x509.Certificate
	expiryUsed bool
	issuerUsed bool
}

func verifyServerCertificate(peer []*x509.Certificate, roots *x509.CertPool, policy ServerTrust, host string, now time.Time) (serverVerification, error) {
	if len(peer) == 0 {
		return serverVerification{}, errors.New("server presented no certificate")
	}
	leaf := peer[0]
	options := x509.VerifyOptions{DNSName: host, Roots: roots, CurrentTime: now, Intermediates: x509.NewCertPool()}
	for _, cert := range peer[1:] {
		options.Intermediates.AddCert(cert)
	}
	checked := leaf
	usedExpiry := false
	if now.After(leaf.NotAfter) && policy.ExpiredServerCertificateGrace > 0 {
		if now.Sub(leaf.NotAfter) > policy.ExpiredServerCertificateGrace || leaf.IsCA {
			return serverVerification{}, errors.New("server leaf expiry exceeds grace or leaf is a CA")
		}
		copyLeaf := *leaf
		copyLeaf.NotAfter = now.Add(time.Nanosecond)
		checked, usedExpiry = &copyLeaf, true
	}
	chains, err := checked.Verify(options)
	if err == nil {
		chain, err := acceptableServerChain(chains, policy, now)
		return serverVerification{chain: chain, expiryUsed: usedExpiry}, err
	}
	var authority x509.UnknownAuthorityError
	if !policy.InsecureAllowUnverifiableIssuer || !errors.As(err, &authority) {
		return serverVerification{}, err
	}
	for _, anchor := range peer {
		selfSignedLeaf := anchor == leaf && bytes.Equal(leaf.RawSubject, leaf.RawIssuer) &&
			leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
		if !selfSignedLeaf && (!anchor.IsCA || !anchor.BasicConstraintsValid || anchor.KeyUsage&x509.KeyUsageCertSign == 0) {
			continue
		}
		if !selfSignedLeaf && slices.ContainsFunc(peer, func(parent *x509.Certificate) bool {
			return parent != anchor && bytes.Equal(anchor.RawIssuer, parent.RawSubject)
		}) {
			continue
		}
		if now.Before(anchor.NotBefore) || now.After(anchor.NotAfter) {
			if !selfSignedLeaf || !usedExpiry {
				continue
			}
		}
		options.Roots = x509.NewCertPool()
		if selfSignedLeaf {
			options.Roots.AddCert(checked)
		} else {
			options.Roots.AddCert(anchor)
		}
		chains, candidateErr := checked.Verify(options)
		if candidateErr != nil {
			continue
		}
		chain, candidateErr := acceptableServerChain(chains, policy, now)
		if candidateErr == nil {
			return serverVerification{chain: chain, expiryUsed: usedExpiry, issuerUsed: true}, nil
		}
	}
	return serverVerification{}, fmt.Errorf("issuer exception could not establish a valid policy-acceptable supplied path: %w", err)
}
