//go:build darwin

package uds

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process at the other end of the socket,
// straight from the kernel (LOCAL_PEERCRED). The client cannot spoof it.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("uds: syscall conn: %w", err)
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("uds: control: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("uds: LOCAL_PEERCRED: %w", credErr)
	}
	return int(cred.Uid), nil
}
