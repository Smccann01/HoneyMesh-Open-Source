package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// meshTLSConfigs keeps the standalone localhost setup working, while requiring
// explicit, verifiable identities before a node participates in a remote mesh.
func meshTLSConfigs(requireExplicit bool, advertisedHost string) (*tls.Config, *tls.Config, error) {
	settings := config.Mesh.TLS
	provided := 0
	for _, path := range []string{settings.CertFile, settings.KeyFile, settings.PeerCAFile, settings.ClientCAFile} {
		if strings.TrimSpace(path) != "" {
			provided++
		}
	}
	if provided != 0 && provided != 4 {
		return nil, nil, fmt.Errorf("mesh TLS requires cert_file, key_file, peer_ca_file and client_ca_file together")
	}
	if requireExplicit && provided != 4 {
		return nil, nil, fmt.Errorf("trusted mesh requires explicit mesh TLS certificate and CA trust; configure mesh.tls before enabling participation")
	}
	if provided == 0 {
		settings = MeshTLSConfig{
			CertFile:     config.Security.CertFile,
			KeyFile:      config.Security.KeyFile,
			PeerCAFile:   config.Security.CACert,
			ClientCAFile: config.Security.CACert,
		}
	}

	cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load mesh certificate: %w", err)
	}
	if provided == 4 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parse mesh certificate: %w", err)
		}
		if advertisedHost == "" {
			return nil, nil, fmt.Errorf("mesh advertised address is empty")
		}
		if err := leaf.VerifyHostname(advertisedHost); err != nil {
			return nil, nil, fmt.Errorf("mesh certificate does not match advertised address %q: %w", advertisedHost, err)
		}
		serverAuth, clientAuth := false, false
		for _, usage := range leaf.ExtKeyUsage {
			serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
			clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
		}
		if !serverAuth || !clientAuth {
			return nil, nil, fmt.Errorf("mesh certificate requires both serverAuth and clientAuth extended key usages")
		}
	}
	peerCAs, err := loadMeshCAPool(settings.PeerCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("peer CA: %w", err)
	}
	clientCAs, err := loadMeshCAPool(settings.ClientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("client CA: %w", err)
	}

	server := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	client := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      peerCAs,
		MinVersion:   tls.VersionTLS13,
	}
	return server, client, nil
}

func loadMeshCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid CA certificates in %q", path)
	}
	return pool, nil
}
