//go:build !linux

package collector

import (
	"errors"
	"net"
)

func ipv6RouteDsts(string) ([]*net.IPNet, error) {
	return nil, errors.New("IPv6 route lookup requires Linux")
}
