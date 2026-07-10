package cidr

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

func ReadCIDRsFromFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ReadCIDRs(f)
}

func ReadCIDRs(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// allow inline comments after space-#
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", line, err)
		}
		out = append(out, p.Masked())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ParseCIDRs(strs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(strs))
	for _, s := range strs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// SplitPrefix splits a prefix into sub-prefixes by increasing the prefix length by step.
// For example, IPv4 /16 with step=2 yields 4 sub-prefixes of /18.
func SplitPrefix(p netip.Prefix, step int) ([]netip.Prefix, error) {
	p = p.Masked()
	if step <= 0 {
		return nil, fmt.Errorf("invalid step: %d", step)
	}
	newBits := p.Bits() + step
	maxBits := 128
	if p.Addr().Is4() {
		maxBits = 32
	}
	if newBits > maxBits {
		return nil, fmt.Errorf("cannot split %s by step %d", p.String(), step)
	}

	parts := 1 << step
	out := make([]netip.Prefix, 0, parts)
	base := p.Addr()

	for i := 0; i < parts; i++ {
		childAddr := childPrefixAddr(base, p.Bits(), step, i)
		out = append(out, netip.PrefixFrom(childAddr, newBits).Masked())
	}
	return out, nil
}

// childPrefixAddr computes the i-th child prefix address when splitting.
// It assumes base is already masked to parentBits so those step bits are 0 and can be ORed.
func childPrefixAddr(base netip.Addr, parentBits int, step int, index int) netip.Addr {
	newBits := parentBits + step
	if base.Is4() {
		a := base.As4()
		v := binary.BigEndian.Uint32(a[:])
		shift := 32 - newBits
		v += uint32(index) << shift
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], v)
		return netip.AddrFrom4(out)
	}
	a := base.As16()
	var out [16]byte
	copy(out[:], a[:])
	shift := 128 - newBits
	orShiftedIndex(&out, uint64(index), shift, step)
	return netip.AddrFrom16(out)
}

func orShiftedIndex(dst *[16]byte, index uint64, shiftFromLSB int, bits int) {
	// Set up to 'bits' bits from index into dst at bit positions [shiftFromLSB, shiftFromLSB+bits).
	for b := 0; b < bits; b++ {
		if (index>>uint(b))&1 == 1 {
			setBitFromLSB(dst, shiftFromLSB+b)
		}
	}
}

// setBitFromLSB sets the bit at position posFromLSB (0 = least significant bit) in big-endian 128-bit buffer.
func setBitFromLSB(dst *[16]byte, posFromLSB int) {
	if posFromLSB < 0 || posFromLSB >= 128 {
		return
	}
	posFromMSB := 127 - posFromLSB
	byteIdx := posFromMSB / 8
	bitInByte := 7 - (posFromMSB % 8)
	dst[byteIdx] |= 1 << uint(bitInByte)
}
