package netaddr

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

var ErrInvalidIPAddress = errors.New("invalid ip address")
var ErrNotIPv4Address = errors.New("not an IPv4 addres")
var ErrNotIPv6Address = errors.New("not an IPv6 addres")

// IPv4ToInt converts IP address of version 4 from net.IP to uint32
// representation.
func IPv4ToInt(ipaddr net.IP) (uint32, error) {
	if ipaddr.To4() == nil {
		return 0, ErrNotIPv4Address
	}
	return binary.LittleEndian.Uint32(ipaddr.To4()), nil
}

// ParseIP implements extension of net.ParseIP. It returns additional
// information about IP address bytes length. In general, it works typically
// as standard net.ParseIP. So if IP is not valid, nil is returned.
func ParseIP(s string) (net.IP, int, error) {
	pip := net.ParseIP(s)
	if pip == nil {
		return nil, 0, ErrInvalidIPAddress
	} else if strings.Contains(s, ".") {
		return pip, 4, nil
	}
	return pip, 16, nil
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}
