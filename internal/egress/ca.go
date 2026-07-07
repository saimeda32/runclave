package egress

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is an ephemeral certificate authority the gateway uses to MITM the specific
// hosts it injects credentials for. It is generated per run; the CA CERT is handed
// to the box (so the box trusts the gateway for those hosts) while the CA KEY never
// leaves the gateway. It mints a leaf per host on demand and caches it.
//
// Residual risk (accepted): a CA the box trusts can sign ANY host, so a compromised
// gateway could MITM hosts beyond the inject list. This is bounded by the CA being
// ephemeral (fresh per run), short-lived (24h), and its key never leaving the
// gateway - and the gateway is runclave's own trusted component.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *rsa.PrivateKey
	mu      sync.Mutex
	leaves  map[string]tls.Certificate
}

// GenerateCA creates a fresh in-memory CA.
func GenerateCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "runclave egress CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, certDER: der, key: key, leaves: map[string]tls.Certificate{}}, nil
}

// CertPEM returns the CA certificate in PEM - this is what the box must trust. The
// CA private key is never exported.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER})
}

// LeafFor mints (and caches) a server certificate for host, signed by the CA.
func (ca *CA) LeafFor(host string) (tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok {
		return c, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// An injected host can be an IP; IPs go in IPAddresses, names in DNSNames, or
	// certificate verification fails.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := tls.Certificate{Certificate: [][]byte{der, ca.certDER}, PrivateKey: key}
	ca.leaves[host] = leaf
	return leaf, nil
}

// InjectRule is the credential to force onto requests to a host: replace Header
// with Value (e.g. Authorization -> "Bearer <real-token>").
type InjectRule struct {
	Header string
	Value  string
}

func (r InjectRule) valid() error {
	if r.Header == "" || r.Value == "" {
		return fmt.Errorf("egress: inject rule needs a header and value")
	}
	return nil
}
