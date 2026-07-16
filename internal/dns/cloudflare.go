package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// CloudflareProvider implements Provider for Cloudflare DNS.
type CloudflareProvider struct {
	token      string
	zoneID     string
	zoneName   string // cached zone name (e.g., "example.com")
	recordType string // "A" or "TXT"
	client     *http.Client
}

// NewCloudflareProvider creates a new Cloudflare DNS provider.
func NewCloudflareProvider(token, zoneID, recordType string) *CloudflareProvider {
	if recordType == "" {
		recordType = "A"
	}
	return &CloudflareProvider{
		token:      token,
		zoneID:     zoneID,
		recordType: recordType,
		client:     &http.Client{},
	}
}

func (p *CloudflareProvider) Name() string {
	return "cloudflare"
}

// cfDNSRecord represents a Cloudflare DNS record.
type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// cfListResponse represents the Cloudflare API list response.
type cfListResponse struct {
	Success bool          `json:"success"`
	Errors  []cfError     `json:"errors"`
	Result  []cfDNSRecord `json:"result"`
}

// cfCreateResponse represents the Cloudflare API create response.
type cfCreateResponse struct {
	Success bool        `json:"success"`
	Errors  []cfError   `json:"errors"`
	Result  cfDNSRecord `json:"result"`
}

// cfDeleteResponse represents the Cloudflare API delete response.
type cfDeleteResponse struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfZoneResponse represents the Cloudflare API zone response.
type cfZoneResponse struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
	Result  struct {
		Name string `json:"name"`
	} `json:"result"`
}

// getZoneName fetches and caches the zone name (domain).
func (p *CloudflareProvider) getZoneName(ctx context.Context) (string, error) {
	if p.zoneName != "" {
		return p.zoneName, nil
	}

	url := fmt.Sprintf("%s/zones/%s", cloudflareAPIBase, p.zoneID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result cfZoneResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return "", fmt.Errorf("cloudflare API error: %s", result.Errors[0].Message)
		}
		return "", fmt.Errorf("cloudflare API error: unknown")
	}

	p.zoneName = result.Result.Name
	return p.zoneName, nil
}

// buildFQDN builds the full domain name from subdomain.
func (p *CloudflareProvider) buildFQDN(ctx context.Context, subdomain string) (string, error) {
	zoneName, err := p.getZoneName(ctx)
	if err != nil {
		return "", fmt.Errorf("get zone name: %w", err)
	}
	if subdomain == "" || subdomain == "@" {
		return zoneName, nil
	}
	return subdomain + "." + zoneName, nil
}

// DeleteRecords deletes all A or AAAA records for the subdomain.
func (p *CloudflareProvider) DeleteRecords(ctx context.Context, subdomain string, ipv6 bool) error {
	recordType := "A"
	if ipv6 {
		recordType = "AAAA"
	}

	// Build full domain name
	fqdn, err := p.buildFQDN(ctx, subdomain)
	if err != nil {
		return err
	}

	// List existing records
	records, err := p.listRecords(ctx, fqdn, recordType)
	if err != nil {
		return err
	}

	// Delete each record
	for _, rec := range records {
		if err := p.deleteRecord(ctx, rec.ID); err != nil {
			return fmt.Errorf("delete record %s: %w", rec.ID, err)
		}
	}
	return nil
}

// CreateRecords creates A/AAAA records for the given IPs.
func (p *CloudflareProvider) CreateRecords(ctx context.Context, subdomain string, ips []netip.Addr) error {
	fqdn, err := p.buildFQDN(ctx, subdomain)
	if err != nil {
		return err
	}

	sem := make(chan struct{}, 5)
	errCh := make(chan error, len(ips))
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			recordType := "A"
			if ip.Is6() {
				recordType = "AAAA"
			}
			if err := p.createRecord(ctx, fqdn, recordType, ip.String()); err != nil {
				errCh <- fmt.Errorf("create record for %s: %w", ip.String(), err)
			}
		}(ip)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

// BatchUpdate atomically replaces all records for the subdomain using Cloudflare's
// DNS Records Batch API (single POST, much faster than delete+create per record).
func (p *CloudflareProvider) BatchUpdate(ctx context.Context, subdomain string, ips []netip.Addr) error {
	fqdn, err := p.buildFQDN(ctx, subdomain)
	if err != nil {
		return err
	}

	if p.recordType == "TXT" {
		return p.batchUpdateTXT(ctx, fqdn, ips)
	}

	return p.batchUpdateA(ctx, fqdn, ips)
}

func (p *CloudflareProvider) batchUpdateTXT(ctx context.Context, fqdn string, ips []netip.Addr) error {
	existing, err := p.listRecords(ctx, fqdn, "TXT")
	if err != nil {
		return fmt.Errorf("list TXT records: %w", err)
	}

	deletes := make([]map[string]string, len(existing))
	for i, rec := range existing {
		deletes[i] = map[string]string{"id": rec.ID}
	}

	posts := make([]map[string]interface{}, len(ips))
	for i, ip := range ips {
		posts[i] = map[string]interface{}{
			"name":    fqdn,
			"type":    "TXT",
			"content": ip.String(),
			"ttl":     1,
		}
	}

	return p.doBatch(ctx, deletes, posts)
}

func (p *CloudflareProvider) batchUpdateA(ctx context.Context, fqdn string, ips []netip.Addr) error {
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	for _, group := range []struct {
		ips   []netip.Addr
		rtype string
	}{
		{v4, "A"},
		{v6, "AAAA"},
	} {
		if len(group.ips) == 0 {
			continue
		}

		existing, err := p.listRecords(ctx, fqdn, group.rtype)
		if err != nil {
			return fmt.Errorf("list %s records: %w", group.rtype, err)
		}

		deletes := make([]map[string]string, len(existing))
		for i, rec := range existing {
			deletes[i] = map[string]string{"id": rec.ID}
		}

		posts := make([]map[string]interface{}, len(group.ips))
		for i, ip := range group.ips {
			posts[i] = map[string]interface{}{
				"name":    fqdn,
				"type":    group.rtype,
				"content": ip.String(),
				"ttl":     1,
				"proxied": false,
			}
		}

		if err := p.doBatch(ctx, deletes, posts); err != nil {
			return err
		}
	}

	return nil
}

func (p *CloudflareProvider) doBatch(ctx context.Context, deletes []map[string]string, posts []map[string]interface{}) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records/batch", cloudflareAPIBase, p.zoneID)
	payload := map[string]interface{}{
		"deletes": deletes,
		"posts":   posts,
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Success bool      `json:"success"`
		Errors  []cfError `json:"errors"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse batch response: %w", err)
	}
	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("batch update: %s", result.Errors[0].Message)
		}
		return fmt.Errorf("batch update: unknown error")
	}

	return nil
}

func (p *CloudflareProvider) listRecords(ctx context.Context, name, recordType string) ([]cfDNSRecord, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records?type=%s&name=%s", cloudflareAPIBase, p.zoneID, recordType, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result cfListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("cloudflare API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("cloudflare API error: unknown")
	}

	return result.Result, nil
}

func (p *CloudflareProvider) deleteRecord(ctx context.Context, recordID string) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, p.zoneID, recordID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result cfDeleteResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("cloudflare API error: %s", result.Errors[0].Message)
		}
		return fmt.Errorf("cloudflare API error: unknown")
	}

	return nil
}

func (p *CloudflareProvider) createRecord(ctx context.Context, name, recordType, content string) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, p.zoneID)

	payload := map[string]interface{}{
		"type":    recordType,
		"name":    name,
		"content": content,
		"ttl":     1, // Auto TTL
		"proxied": false,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result cfCreateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("cloudflare API error: %s", result.Errors[0].Message)
		}
		return fmt.Errorf("cloudflare API error: unknown")
	}

	return nil
}
