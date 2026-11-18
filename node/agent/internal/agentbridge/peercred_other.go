//go:build !linux

package agentbridge

import (
	"errors"
	"net"
)

func unixPeerUID(net.Conn) (uint32, error) {
	return 0, errors.New("Unix peer UID check requires Linux")
}
