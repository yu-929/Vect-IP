//go:build !windows

package server

import (
	"context"
	"fmt"
	"net"
	"os"
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

	icmpFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil
	}
	defer syscall.Close(icmpFd)

	tv := syscall.NsecToTimeval(2 * 1e9)
	syscall.SetsockoptTimeval(icmpFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	probeID := int16(os.Getpid() & 0xFFFF)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], target4)

	icmpPayload := make([]byte, 8)
	icmpPayload[0] = 8
	icmpPayload[1] = 0
	icmpPayload[2] = 0
	icmpPayload[3] = 0
	icmpPayload[4] = byte(probeID >> 8)
	icmpPayload[5] = byte(probeID)
	icmpPayload[6] = 0
	icmpPayload[7] = 0

	var hops []TracerouteHop
	destReached := false

	for ttl := 1; ttl <= 30 && !destReached; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}

		syscall.SetsockoptInt(icmpFd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)

		icmpPayload[6] = byte(ttl >> 8)
		icmpPayload[7] = byte(ttl)

		cksum := icmpChecksum(icmpPayload)
		icmpPayload[2] = byte(cksum >> 8)
		icmpPayload[3] = byte(cksum)

		start := time.Now()
		err := syscall.Sendto(icmpFd, icmpPayload, 0, &addr)
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
			ipHeaderLen := int(buf[0]&0x0F) * 4
			if ipHeaderLen < 20 || n < ipHeaderLen+8 {
				hops = append(hops, TracerouteHop{Hop: ttl, IP: "*", MS: "", Lost: true})
				continue
			}
			icmpType := buf[ipHeaderLen]
			icmpCode := buf[ipHeaderLen+1]

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
			case icmpType == 0 && icmpCode == 0:
				hops = append(hops, TracerouteHop{Hop: ttl, IP: hopIP, MS: ms, Lost: false})
				destReached = true
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

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}