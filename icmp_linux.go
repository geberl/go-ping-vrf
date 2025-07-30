package ping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func bindInterface(fd int, sourceInterface string) error {
	err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, sourceInterface)
	if err != nil {
		return fmt.Errorf("error setting socket options: %v\n", err)
	}
	return nil
}

// Copied from golang.org/x/net@v0.0.0-20200904194848-62affa334b73/icmp/listen_posix.go and modified

// ListenPacket listens for incoming ICMP packets addressed to
// address. See net.Dial for the syntax of address.
//
// For non-privileged datagram-oriented ICMP endpoints, network must
// be "udp4" or "udp6". The endpoint allows to read, write a few
// limited ICMP messages such as echo request and echo reply.
// Currently only Darwin and Linux support this.
//
// Examples:
//	ListenPacket("udp4", "192.168.0.1")
//	ListenPacket("udp4", "0.0.0.0")
//	ListenPacket("udp6", "fe80::1%en0")
//	ListenPacket("udp6", "::")
//
// For privileged raw ICMP endpoints, network must be "ip4" or "ip6"
// followed by a colon and an ICMP protocol number or name.
//
// Examples:
//	ListenPacket("ip4:icmp", "192.168.0.1")
//	ListenPacket("ip4:1", "0.0.0.0")
//	ListenPacket("ip6:ipv6-icmp", "fe80::1%en0")
//	ListenPacket("ip6:58", "::")
func ListenPacket(network, address, sourceInterface string) (*PacketConn, error) {
	var proto int
	i := last(network, ':')
	if i < 0 {
		i = len(network)
	}
	switch network[:i] {
	case "ip4":
		proto = ProtocolICMP
	case "ip6":
		proto = ProtocolIPv6ICMP
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			var bindErr error
			ctrlErr := c.Control(func(fd uintptr) {
				bindErr = bindInterface(int(fd), sourceInterface)
			})
			if bindErr != nil {
				return bindErr
			}
			return ctrlErr
		},
	}

	c, cerr := lc.ListenPacket(context.Background(), network, address)
	if cerr != nil {
		return nil, cerr
	}

	switch proto {
	case ProtocolICMP:
		return &PacketConn{c: c, p4: ipv4.NewPacketConn(c)}, nil
	case ProtocolIPv6ICMP:
		return &PacketConn{c: c, p6: ipv6.NewPacketConn(c)}, nil
	default:
		return &PacketConn{c: c}, nil
	}
}

// Copied from golang.org/x/net@v0.0.0-20200904194848-62affa334b73/icmp/helper_posix.go because not exported

func last(s string, b byte) int {
	i := len(s)
	for i--; i >= 0; i-- {
		if s[i] == b {
			break
		}
	}
	return i
}

// Copied from golang.org/x/net@v0.0.0-20200904194848-62affa334b73/internal/iana/const.go because import marked as internal

const (
	ProtocolICMP     = 1  // Internet Control Message
	ProtocolIPv6ICMP = 58 // ICMP for IPv6
)

// Copied from golang.org/x/net@v0.0.0-20200904194848-62affa334b73/icmp/endpoint.go because struct fields not exported

var _ net.PacketConn = &PacketConn{}

// A PacketConn represents a packet network endpoint that uses either
// ICMPv4 or ICMPv6.
type PacketConn struct {
	c  net.PacketConn
	p4 *ipv4.PacketConn
	p6 *ipv6.PacketConn
}

func (c *PacketConn) ok() bool { return c != nil && c.c != nil }

// IPv4PacketConn returns the ipv4.PacketConn of c.
// It returns nil when c is not created as the endpoint for ICMPv4.
func (c *PacketConn) IPv4PacketConn() *ipv4.PacketConn {
	if !c.ok() {
		return nil
	}
	return c.p4
}

// IPv6PacketConn returns the ipv6.PacketConn of c.
// It returns nil when c is not created as the endpoint for ICMPv6.
func (c *PacketConn) IPv6PacketConn() *ipv6.PacketConn {
	if !c.ok() {
		return nil
	}
	return c.p6
}

// ReadFrom reads an ICMP message from the connection.
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.ok() {
		return 0, nil, errInvalidConn
	}
	// Please be informed that ipv4.NewPacketConn enables
	// IP_STRIPHDR option by default on Darwin.
	// See golang.org/issue/9395 for further information.
	if runtime.GOOS == "darwin" && c.p4 != nil {
		n, _, peer, err := c.p4.ReadFrom(b)
		return n, peer, err
	}
	return c.c.ReadFrom(b)
}

// WriteTo writes the ICMP message b to dst.
// The provided dst must be net.UDPAddr when c is a non-privileged
// datagram-oriented ICMP endpoint.
// Otherwise it must be net.IPAddr.
func (c *PacketConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if !c.ok() {
		return 0, errInvalidConn
	}
	return c.c.WriteTo(b, dst)
}

// Close closes the endpoint.
func (c *PacketConn) Close() error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.Close()
}

// LocalAddr returns the local network address.
func (c *PacketConn) LocalAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.c.LocalAddr()
}

// SetDeadline sets the read and write deadlines associated with the
// endpoint.
func (c *PacketConn) SetDeadline(t time.Time) error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the
// endpoint.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the
// endpoint.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return errInvalidConn
	}
	return c.c.SetWriteDeadline(t)
}

// Copied from golang.org/x/net@v0.0.0-20200904194848-62affa334b73/icmp/message.go because var not exported

var errInvalidConn = errors.New("invalid connection")
