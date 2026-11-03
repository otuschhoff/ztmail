package mail

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"time"
)

func PrepareAuthentication(c Config) (Config, error) {
	if c.Auth == "" {
		c.Auth = AuthGSSAPI
	}
	switch c.Auth {
	case AuthGSSAPI:
		if c.ClientCertificate != nil {
			return Config{}, errors.New("GSSAPI cannot be combined with a TLS client certificate")
		}
	case AuthMTLS, AuthMTLSExternal:
		if c.ClientCertificate == nil {
			return Config{}, errors.New("mTLS requires a client certificate and private key")
		}
	default:
		return Config{}, errors.New("authentication method must be gssapi, mtls, or mtls-external")
	}
	var err error
	c.ServerTrust, err = cloneServerTrust(c.ServerTrust)
	if err != nil {
		return Config{}, err
	}
	if c.TLSMode == "off" && (c.Auth != AuthGSSAPI || c.ServerTrust.Mode != RootsSystem ||
		len(c.ServerTrust.Allow)+len(c.ServerTrust.Deny) > 0 || c.ServerTrust.ExpiredServerCertificateGrace > 0 ||
		c.ServerTrust.InsecureAllowUnverifiableIssuer) {
		return Config{}, errors.New("TLS authentication/trust options cannot be used with TLS off")
	}
	if c.ClientCertificate != nil {
		c.ClientCertificate, err = cloneClientCertificate(c.ClientCertificate)
		if err != nil {
			return Config{}, err
		}
	}
	return c, nil
}

func cloneClientCertificate(input *tls.Certificate) (*tls.Certificate, error) {
	if len(input.Certificate) == 0 || input.PrivateKey == nil {
		return nil, errors.New("client certificate requires a chain and private key")
	}
	signer, ok := input.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("client private key must support signing")
	}
	result := *input
	result.Certificate = make([][]byte, len(input.Certificate))
	for i, der := range input.Certificate {
		result.Certificate[i] = bytes.Clone(der)
		cert, err := x509.ParseCertificate(result.Certificate[i])
		if err != nil {
			return nil, fmt.Errorf("client certificate %d: %w", i+1, err)
		}
		if i == 0 {
			result.Leaf = cert
		}
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("client signing key: %w", err)
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(result.Leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public, leafPublic) {
		return nil, errors.New("client certificate does not match private key")
	}
	result.OCSPStaple = bytes.Clone(input.OCSPStaple)
	result.SupportedSignatureAlgorithms = slices.Clone(input.SupportedSignatureAlgorithms)
	result.SignedCertificateTimestamps = make([][]byte, len(input.SignedCertificateTimestamps))
	for i, value := range input.SignedCertificateTimestamps {
		result.SignedCertificateTimestamps[i] = bytes.Clone(value)
	}
	return &result, nil
}

func validateClientCertificate(cert *tls.Certificate, now time.Time) error {
	if now.Before(cert.Leaf.NotBefore) || now.After(cert.Leaf.NotAfter) {
		return errors.New("client certificate is expired or not yet valid")
	}
	if len(cert.Leaf.ExtKeyUsage) > 0 && !slices.Contains(cert.Leaf.ExtKeyUsage, x509.ExtKeyUsageAny) &&
		!slices.Contains(cert.Leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return errors.New("client certificate EKU excludes TLS client authentication")
	}
	if cert.Leaf.KeyUsage != 0 && cert.Leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("client certificate key usage excludes TLS signatures")
	}
	return nil
}

func LoadClientCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read client certificate: %w", err)
	}
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("open client private key: %w", err)
	}
	stat, statErr := keyFile.Stat()
	var keyPEM []byte
	if statErr == nil {
		if !stat.Mode().IsRegular() || (runtime.GOOS != "windows" && stat.Mode().Perm()&0077 != 0) {
			statErr = errors.New("client private key must be a regular owner-private file (no group/world access)")
		} else {
			keyPEM, statErr = io.ReadAll(keyFile)
		}
	}
	if err := errors.Join(statErr, keyFile.Close()); err != nil {
		return nil, fmt.Errorf("read client private key: %w", err)
	}
	defer clear(keyPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate/private key: %w", err)
	}
	return cloneClientCertificate(&cert)
}

func LoadServerCAs(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SMTP CA bundle: %w", err)
	}
	var result [][]byte
	for len(bytes.TrimSpace(data)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("SMTP CA bundle contains non-certificate or malformed PEM")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("SMTP CA bundle contains invalid certificate PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("SMTP CA certificate: %w", err)
		}
		result = append(result, bytes.Clone(block.Bytes))
		data = rest
	}
	if len(result) == 0 {
		return nil, errors.New("SMTP CA bundle contains no certificates")
	}
	return result, nil
}
