package main

import "fmt"

// revokeMeshPeer persists the certificate denial before reporting success.
func revokeMeshPeer(peer string) error {
	if scp == nil {
		return fmt.Errorf("mesh is not running")
	}
	fingerprint, ok := scp.RevokePeer(peer)
	if !ok {
		return fmt.Errorf("peer certificate is unknown; wait for a heartbeat before revoking")
	}
	config.Mesh.RevokedPeerCerts = append(config.Mesh.RevokedPeerCerts, fingerprint)
	if !saveConfig() {
		return fmt.Errorf("peer denied locally, but revocation could not be persisted")
	}
	removePeer(peer)
	return nil
}
