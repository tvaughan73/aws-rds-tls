package rdstls

import (
	"crypto/tls"
	"crypto/x509"
)

func CreateRDSTLSConf() (tlsConfig *tls.Config, err error) {
	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM([]byte(AWSRDSRootCert)); !ok {
		return nil, err
	}
	return &tls.Config{ //nolint:gosec
		RootCAs:    rootCertPool,
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
	}, nil
}
