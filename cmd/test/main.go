package main

import (
	"fmt"
	"net"

	"github.com/cybwan/l4gw/pkg/netaddr"
)

func main() {
	ipAddrs := []string{
		`192.168.226.21`,
		`192.168.226.22`,
		`192.168.127.22`,
		`192.168.127.31`,
		`18.208.239.112`,
		`8.8.8.8`,
	}
	for _, ipAddr := range ipAddrs {
		ipNb, _ := netaddr.IPv4ToInt(net.ParseIP(ipAddr))
		fmt.Printf("%-16s %-10d\n", ipAddr, ipNb)
	}

}
