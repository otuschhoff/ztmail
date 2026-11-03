package mail

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"net/textproto"
	"slices"
	"strings"
	"time"
)

type CertificateInfo struct {
	Subject, Issuer, SHA256                string
	NotBefore, NotAfter                    time.Time
	PublicKeyAlgorithm, SignatureAlgorithm string
}

type ServerVerificationInfo struct {
	RootMode                                 RootMode
	AnchorSHA256                             string
	Trusted                                  bool
	ExpiryGrace                              time.Duration
	IssuerExceptionConfigured                bool
	ExpiryExceptionUsed, IssuerExceptionUsed bool
}

type AuthenticationResult struct {
	Method                     AuthMode
	ClientCertificateRequested bool
	ClientCertificatePresented bool
	SMTPAuthConfirmed          bool
	ClientCertificate          *CertificateInfo
	ServerVerification         ServerVerificationInfo
}

func certificateInfo(cert *x509.Certificate) *CertificateInfo {
	hash := sha256.Sum256(cert.Raw)
	return &CertificateInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SHA256: hex.EncodeToString(hash[:]),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), SignatureAlgorithm: cert.SignatureAlgorithm.String()}
}

func authenticationTLS(o options, log io.Writer) (*tls.Config, *AuthenticationResult, error) {
	method := o.auth
	if method == "" {
		method = AuthGSSAPI
	}
	evidence := &AuthenticationResult{Method: method}
	evidence.ServerVerification.RootMode = o.serverTrust.Mode
	if evidence.ServerVerification.RootMode == "" {
		evidence.ServerVerification.RootMode = RootsSystem
	}
	evidence.ServerVerification.ExpiryGrace = o.serverTrust.ExpiredServerCertificateGrace
	evidence.ServerVerification.IssuerExceptionConfigured = o.serverTrust.InsecureAllowUnverifiableIssuer
	roots, err := serverRoots(o.serverTrust)
	if err != nil {
		return nil, nil, err
	}
	config := &tls.Config{ServerName: o.relay, MinVersion: tls.VersionTLS12, RootCAs: roots}
	relaxed := o.serverTrust.ExpiredServerCertificateGrace > 0 || o.serverTrust.InsecureAllowUnverifiableIssuer
	if relaxed {
		detail := fmt.Sprintf("explicit insecure server TLS options: expiry grace=%s; unverifiable issuer=%t; hostname and non-exempt checks remain required",
			o.serverTrust.ExpiredServerCertificateGrace, o.serverTrust.InsecureAllowUnverifiableIssuer)
		if o.report != nil {
			o.report.Line("WARN", "Server TLS policy", detail)
		} else {
			fmt.Fprintln(log, "Warning:", detail)
		}
		// The paired callback below enforces every non-exempt check.
		config.InsecureSkipVerify = true
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		now := time.Now()
		var verification serverVerification
		var err error
		if relaxed {
			verification, err = verifyServerCertificate(state.PeerCertificates, roots, o.serverTrust, o.relay, now)
		} else {
			verification.chain, err = acceptableServerChain(state.VerifiedChains, o.serverTrust, now)
		}
		if err != nil {
			return err
		}
		if len(verification.chain) == 0 {
			return errors.New("server verification produced no certificate chain")
		}
		anchor := verification.chain[len(verification.chain)-1]
		evidence.ServerVerification.AnchorSHA256 = certificateInfo(anchor).SHA256
		evidence.ServerVerification.Trusted = !verification.issuerUsed
		evidence.ServerVerification.ExpiryExceptionUsed = verification.expiryUsed
		evidence.ServerVerification.IssuerExceptionUsed = verification.issuerUsed
		if verification.expiryUsed || verification.issuerUsed {
			detail := fmt.Sprintf("server verification relaxed: expired leaf=%t; untrusted issuer=%t; server SHA256=%s",
				verification.expiryUsed, verification.issuerUsed, certificateInfo(state.PeerCertificates[0]).SHA256)
			if o.report != nil {
				o.report.Line("WARN", "Server TLS verification exception", detail)
			} else {
				fmt.Fprintln(log, "Warning:", detail)
			}
		}
		return nil
	}
	if method != AuthGSSAPI {
		if err := validateClientCertificate(o.clientCertificate, time.Now()); err != nil {
			return nil, nil, err
		}
		evidence.ClientCertificate = certificateInfo(o.clientCertificate.Leaf)
		config.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			evidence.ClientCertificateRequested = true
			if err := validateClientCertificate(o.clientCertificate, time.Now()); err != nil {
				return nil, err
			}
			if err := request.SupportsCertificate(o.clientCertificate); err != nil {
				return nil, fmt.Errorf("client certificate incompatible with relay request: %w", err)
			}
			evidence.ClientCertificatePresented = true
			return o.clientCertificate, nil
		}
	}
	return config, evidence, nil
}

func externalAuthentication(c *smtp.Client) error {
	ok, mechanisms := c.Extension("AUTH")
	if !ok || !slices.ContainsFunc(strings.Fields(mechanisms), func(s string) bool { return strings.EqualFold(s, "EXTERNAL") }) {
		return errors.New("relay does not advertise AUTH EXTERNAL after TLS")
	}
	command := func(value string) (int, string, error) {
		id, err := c.Text.Cmd("%s", value)
		if err != nil {
			return 0, "", err
		}
		c.Text.StartResponse(id)
		defer c.Text.EndResponse(id)
		return c.Text.ReadResponse(0)
	}
	code, message, err := command("AUTH EXTERNAL =")
	if err != nil {
		return err
	}
	if code == 334 {
		if message != "" {
			return errors.New("unexpected non-empty SMTP EXTERNAL challenge")
		}
		code, message, err = command("=")
		if err != nil {
			return err
		}
	}
	if code != 235 {
		return &textproto.Error{Code: code, Msg: message}
	}
	return nil
}

func reportAuthentication(o options, result AuthenticationResult) {
	o.report.authenticationResult(result)
	if o.authentication != nil {
		if result.ClientCertificate != nil {
			copyCertificate := *result.ClientCertificate
			result.ClientCertificate = &copyCertificate
		}
		o.authentication(result)
	}
}

func (r *TestReport) authenticationResult(result AuthenticationResult) {
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.authentication = result
	}
}
