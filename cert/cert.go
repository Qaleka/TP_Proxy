package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	caMaxAge   = 10 * 365 * 24 * time.Hour 
	leafMaxAge = 24 * time.Hour          
	rsaKeySize = 2048
)

func GenCA(name string) ([]byte, []byte, error) {
	now := time.Now()
	
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации ключа: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка создания сертификата: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certPEM, keyPEM, nil
}

func GenCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	if ca.Leaf == nil {
		leaf, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("ошибка разбора CA сертификата: %w", err)
		}
		ca.Leaf = leaf
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(leafMaxAge),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              names,
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации ключа: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания сертификата: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        tmpl,
	}, nil
}