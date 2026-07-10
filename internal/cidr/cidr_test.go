package cidr

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseCIDRs(t *testing.T) {
	cidrs, err := ParseCIDRs([]string{"1.1.0.0/16", "1.2.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

func TestParseCIDRsEmpty(t *testing.T) {
	cidrs, err := ParseCIDRs([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected 0 CIDRs, got %d", len(cidrs))
	}
}

func TestParseCIDRsInvalid(t *testing.T) {
	_, err := ParseCIDRs([]string{"invalid"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestReadCIDRs(t *testing.T) {
	input := "1.1.0.0/16\n# comment\n1.2.0.0/24\n\n1.3.0.0/24 # inline comment\n"
	r := strings.NewReader(input)
	cidrs, err := ReadCIDRs(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 3 {
		t.Errorf("expected 3 CIDRs, got %d", len(cidrs))
	}
}

func TestSplitPrefixV4(t *testing.T) {
	prefix := netip.MustParsePrefix("1.1.0.0/16")
	children, err := SplitPrefix(prefix, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 4 {
		t.Errorf("expected 4 children (2^2), got %d", len(children))
	}

	expected := []string{"1.1.0.0/18", "1.1.64.0/18", "1.1.128.0/18", "1.1.192.0/18"}
	for i, child := range children {
		if child.String() != expected[i] {
			t.Errorf("child %d: expected %s, got %s", i, expected[i], child.String())
		}
	}
}

func TestSplitPrefixV6(t *testing.T) {
	prefix := netip.MustParsePrefix("2606:4700::/32")
	children, err := SplitPrefix(prefix, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 16 {
		t.Errorf("expected 16 children (2^4), got %d", len(children))
	}
}

func TestSplitPrefixInvalidStep(t *testing.T) {
	prefix := netip.MustParsePrefix("1.1.0.0/16")
	_, err := SplitPrefix(prefix, -1)
	if err == nil {
		t.Error("expected error for negative step")
	}
}

func TestSplitPrefixTooLarge(t *testing.T) {
	prefix := netip.MustParsePrefix("1.1.0.0/31")
	_, err := SplitPrefix(prefix, 2)
	if err == nil {
		t.Error("expected error for splitting /31 by step 2 (would exceed /32)")
	}
}

func TestChildPrefixAddrV4(t *testing.T) {
	base := netip.MustParsePrefix("1.1.0.0/16").Addr()
	addr := childPrefixAddr(base, 16, 2, 0)
	expected := netip.MustParsePrefix("1.1.0.0/18").Addr()
	if addr != expected {
		t.Errorf("expected %s, got %s", expected, addr)
	}

	addr = childPrefixAddr(base, 16, 2, 1)
	expected = netip.MustParsePrefix("1.1.64.0/18").Addr()
	if addr != expected {
		t.Errorf("expected %s, got %s", expected, addr)
	}
}

func TestChildPrefixAddrV6(t *testing.T) {
	base := netip.MustParsePrefix("2606:4700::/32").Addr()
	addr := childPrefixAddr(base, 32, 4, 0)
	expected := netip.MustParsePrefix("2606:4700::/36").Addr()
	if addr != expected {
		t.Errorf("expected %s, got %s", expected, addr)
	}
}

func TestSetBitFromLSB(t *testing.T) {
	var buf [16]byte
	setBitFromLSB(&buf, 127) // MSB of first byte
	if buf[0] != 0x80 {
		t.Errorf("expected 0x80, got 0x%02x", buf[0])
	}

	setBitFromLSB(&buf, 0) // LSB of last byte
	if buf[15] != 0x01 {
		t.Errorf("expected 0x01, got 0x%02x", buf[15])
	}
}

func TestOrShiftedIndex(t *testing.T) {
	var dst [16]byte
	orShiftedIndex(&dst, 1, 0, 1)
	if dst[15] != 0x01 {
		t.Errorf("expected 0x01, got 0x%02x", dst[15])
	}
}