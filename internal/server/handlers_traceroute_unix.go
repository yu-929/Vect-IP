//go:build !windows

package server

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

func runGoTraceroute(ctx context.Context, ip string) []TracerouteHop {
	target := net.ParseIP(ip)
	if target == nil {
		return nil
	}
	target4 := target.To4()
	if target4 == nil {
		return nil
	}

	probeFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil
	}
	defer syscall.Close(probeFd)

	useRaw := false
	icmpFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err == nil {
		useRaw = true
	} else {
		icmpFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
		if err != nil {
			return nil
		}
	}
	defer syscall.Close(icmpFd)

	tv := syscall.NsecToTimeval(3 * 1e9)
	syscall.SetsockoptTimeval(icmpFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], target4)

	var hops []TracerouteHop
	destReached := false

	for ttl := 1; ttl <= 30 && !destReached; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}

		syscall.SetsockoptInt(probeFd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		addr.Port = 33434 + ttl
		start := time.Now()

		err := syscall.Sendto(probeFd, nil, 0, &addr)
		if err != nil {
			hops = append(hops, TracerouteHop{Hop: ttl, IP: "*", MS: "", Lost: true})
			continue
		}

		buf := make([]byte, 512)
		n, from, err := syscall.Recvfrom(icmpFd, buf, 0)
		elapsed := time.Since(start)

		if err != nil {
			hops = append(hops, TracerouteHop{Hop: ttl, IP: "*", MS: "", Lost: true})
			continue
		}

		if n >= 8 {
			var icmpType, icmpCode byte
			if useRaw {
				ipHeaderLen := int(buf[0]&0x0F) * 4
				icmpType = buf[ipHeaderLen]
				icmpCode = buf[ipHeaderLen+1]
			} else {
				icmpType = buf[0]
				icmpCode = buf[1]
			}

			fromAddr, ok := from.(*syscall.SockaddrInet4)
			if !ok {
				hops = append(hops, TracerouteHop{Hop: ttl, IP: "*", MS: "", Lost: true})
				continue
			}
			hopIP := net.IP(fromAddr.Addr[:]).String()
			ms := fmt.Sprintf("%.1f", float64(elapsed.Microseconds())/1000.0)

			switch {
			case icmpType == 11 && icmpCode == 0:
				hops = append(hops, TracerouteHop{Hop: ttl, IP: hopIP, MS: ms, Lost: false})
			case icmpType == 3:
				hops = append(hops, TracerouteHop{Hop: ttl, IP: hopIP, MS: ms, Lost: false})
				destReached = true
			default:
				hops = append(hops, TracerouteHop{Hop: ttl, IP: "*", MS: "", Lost: true})
			}
		} else {
			hops = append(hops, TracerouteHop{Hop: ttl, IP: "*", MS: "", Lost: true})
		}
	}

	return hops
}