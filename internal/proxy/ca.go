package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CertificateAuthority struct {
	cert  *x509.Certificate
	key   crypto.Signer
	cache map[string]tlsCertificate
	mu    sync.Mutex
}

type tlsCertificate struct {
	certPEM []byte
	keyPEM  []byte
}

func LoadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("HTTPS decryption requires both --proxy-ca-cert and --proxy-ca-key; a DER certificate alone cannot sign leaf certificates")
	}
	cert, err := loadCert(certPath)
	if err != nil {
		return nil, err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA certificate %s is not marked as a CA", certPath)
	}
	return &CertificateAuthority{cert: cert, key: key, cache: map[string]tlsCertificate{}}, nil
}

func GenerateCAFiles(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("CA output paths are required")
	}
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil && filepath.Dir(certPath) != "." {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil && filepath.Dir(keyPath) != "." {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Authorized Scanner Local CA", Organization: []string{"Authorized Scanner"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0600)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return cert, nil
}

func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block != nil {
		b = block.Bytes
	}
	if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		return signerFromKey(k)
	}
	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(b); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("parse CA private key: unsupported or encrypted key format")
}

func signerFromKey(k any) (crypto.Signer, error) {
	switch key := k.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
}

func (ca *CertificateAuthority) Leaf(host string) (tlsCertificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	ca.mu.Lock()
	if cert, ok := ca.cache[host]; ok {
		ca.mu.Unlock()
		return cert, nil
	}
	ca.mu.Unlock()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsCertificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tlsCertificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, leafKey.Public(), ca.key)
	if err != nil {
		return tlsCertificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return tlsCertificate{}, err
	}
	out := tlsCertificate{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	ca.mu.Lock()
	ca.cache[host] = out
	ca.mu.Unlock()
	return out, nil
}
