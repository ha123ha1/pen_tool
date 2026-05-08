package proxy

import (
	"crypto/tls"
	"path/filepath"
	"testing"
)

func TestGenerateLoadAndSignLeaf(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "scanner-ca.pem")
	keyPath := filepath.Join(dir, "scanner-ca-key.pem")
	if err := GenerateCAFiles(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(leaf.certPEM, leaf.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("leaf certificate is empty")
	}
}
