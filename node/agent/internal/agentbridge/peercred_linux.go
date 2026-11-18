//go:build linux

package agentbridge

import (
	"errors"
	"net"
	"syscall"
)

func unixPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("peer is not a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		var cred *syscall.Ucred
		cred, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if socketErr == nil {
			uid = cred.Uid
		}
	}); err != nil {
		return 0, err
	}
	return uid, socketErr
}
