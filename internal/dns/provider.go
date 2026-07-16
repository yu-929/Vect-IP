// Package dns provides DNS resolution via Cloudflare, Vercel and custom providers.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Config holds DNS upload configuration.
type Config struct {
	Provider    string // "cloudflare" or "vercel"
	Token       string // API token
	Zone        string // Zone ID (Cloudflare) or domain (Vercel)
	Subdomain   string // Subdomain prefix (e.g., "cf" for cf.example.com)
	UploadCount int    // Number of IPs to upload
	TeamID      string // Vercel Team ID (optional)
	RecordType  string // "A" or "TXT" (Cloudflare only, default "A")
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
		return NewCloudflareProvider(token, zone, cfg.RecordType), nil

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

const availabilityCheckURL = "https://api.090227.xyz/check"

// FilterIPv6OnlyByAPI calls the availability check API for each IP and returns
// only IPs whose inferred_stack is not "ipv6_only". On API errors the IP is kept.
func FilterIPv6OnlyByAPI(ips []netip.Addr) []netip.Addr {
	type result struct {
		ip   netip.Addr
		keep bool
	}
	ch := make(chan result, len(ips))
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 3 * time.Second}
	for _, ip := range ips {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			url := fmt.Sprintf("%s?proxyip=%s:443", availabilityCheckURL, ip.String())
			resp, err := client.Get(url)
			if err != nil {
				ch <- result{ip, true}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			var data struct {
				InferredStack string `json:"inferred_stack"`
			}
			if err := json.Unmarshal(body, &data); err != nil {
				ch <- result{ip, true}
				return
			}
			ch <- result{ip, data.InferredStack != "ipv6_only"}
		}(ip)
	}
	wg.Wait()
	close(ch)

	var filtered []netip.Addr
	for r := range ch {
		if r.keep {
			filtered = append(filtered, r.ip)
		}
	}
	return filtered
}

// Upload uploads the given IPs to the DNS provider.
// It first deletes existing records for the subdomain, then creates new ones.
func Upload(ctx context.Context, provider Provider, subdomain string, ips []netip.Addr, verbose bool) error {
	if len(ips) == 0 {
		return nil
	}

	// Use batch update if provider supports it (faster: single API call)
	if bp, ok := provider.(interface {
		BatchUpdate(ctx context.Context, subdomain string, ips []netip.Addr) error
	}); ok {
		return bp.BatchUpdate(ctx, subdomain, ips)
	}

	// Fall back to delete + create
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
