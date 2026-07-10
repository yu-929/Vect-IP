package dns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
)

// Config holds DNS upload configuration.
type Config struct {
	Provider    string // "cloudflare" or "vercel"
	Token       string // API token
	Zone        string // Zone ID (Cloudflare) or domain (Vercel)
	Subdomain   string // Subdomain prefix (e.g., "cf" for cf.example.com)
	UploadCount int    // Number of IPs to upload
	TeamID      string // Vercel Team ID (optional)
}

// Provider defines the interface for DNS record management.
type Provider interface {
	// Name returns the provider name.
	Name() string
	// DeleteRecords deletes all A or AAAA records for the subdomain.
	DeleteRecords(ctx context.Context, subdomain string, ipv6 bool) error
	// CreateRecords creates A/AAAA records for the given IPs.
	CreateRecords(ctx context.Context, subdomain string, ips []netip.Addr) error
}

// NewProvider creates a Provider based on the config.
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case "cloudflare":
		token := cfg.Token
		if token == "" {
			token = os.Getenv("CF_API_TOKEN")
		}
		zone := cfg.Zone
		if zone == "" {
			zone = os.Getenv("CF_ZONE_ID")
		}
		if token == "" {
			return nil, fmt.Errorf("cloudflare: API token required (--dns-token or CF_API_TOKEN)")
		}
		if zone == "" {
			return nil, fmt.Errorf("cloudflare: zone ID required (--dns-zone or CF_ZONE_ID)")
		}
		return NewCloudflareProvider(token, zone), nil

	case "vercel":
		token := cfg.Token
		if token == "" {
			token = os.Getenv("VERCEL_TOKEN")
		}
		teamID := cfg.TeamID
		if teamID == "" {
			teamID = os.Getenv("VERCEL_TEAM_ID")
		}
		domain := cfg.Zone
		if token == "" {
			return nil, fmt.Errorf("vercel: API token required (--dns-token or VERCEL_TOKEN)")
		}
		if domain == "" {
			return nil, fmt.Errorf("vercel: domain required (--dns-zone)")
		}
		return NewVercelProvider(token, domain, teamID), nil

	default:
		return nil, fmt.Errorf("unknown DNS provider: %s (supported: cloudflare, vercel)", cfg.Provider)
	}
}

// Upload uploads the given IPs to the DNS provider.
// It first deletes existing records for the subdomain, then creates new ones.
func Upload(ctx context.Context, provider Provider, subdomain string, ips []netip.Addr, verbose bool) error {
	if len(ips) == 0 {
		return nil
	}

	// Separate IPv4 and IPv6 addresses
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	// Delete existing A records and create new ones
	if len(v4) > 0 {
		if verbose {
			fmt.Fprintf(os.Stderr, "dns: deleting existing A records for %s...\n", subdomain)
		}
		if err := provider.DeleteRecords(ctx, subdomain, false); err != nil {
			return fmt.Errorf("delete A records: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "dns: creating %d A records for %s...\n", len(v4), subdomain)
		}
		if err := provider.CreateRecords(ctx, subdomain, v4); err != nil {
			return fmt.Errorf("create A records: %w", err)
		}
	}

	// Delete existing AAAA records and create new ones
	if len(v6) > 0 {
		if verbose {
			fmt.Fprintf(os.Stderr, "dns: deleting existing AAAA records for %s...\n", subdomain)
		}
		if err := provider.DeleteRecords(ctx, subdomain, true); err != nil {
			return fmt.Errorf("delete AAAA records: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "dns: creating %d AAAA records for %s...\n", len(v6), subdomain)
		}
		if err := provider.CreateRecords(ctx, subdomain, v6); err != nil {
			return fmt.Errorf("create AAAA records: %w", err)
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "dns: upload complete (%d A, %d AAAA records)\n", len(v4), len(v6))
	}
	return nil
}
