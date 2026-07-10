package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

const vercelAPIBase = "https://api.vercel.com"

// VercelProvider implements Provider for Vercel DNS.
type VercelProvider struct {
	token  string
	domain string
	teamID string
	client *http.Client
}

// NewVercelProvider creates a new Vercel DNS provider.
func NewVercelProvider(token, domain, teamID string) *VercelProvider {
	return &VercelProvider{
		token:  token,
		domain: domain,
		teamID: teamID,
		client: &http.Client{},
	}
}

func (p *VercelProvider) Name() string {
	return "vercel"
}

// vercelDNSRecord represents a Vercel DNS record.
type vercelDNSRecord struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// vercelListResponse represents the Vercel API list response.
type vercelListResponse struct {
	Records    []vercelDNSRecord `json:"records"`
	Pagination struct {
		Count int    `json:"count"`
		Next  string `json:"next"`
		Prev  string `json:"prev"`
	} `json:"pagination"`
}

// vercelErrorResponse represents a Vercel API error response.
type vercelErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// DeleteRecords deletes all A or AAAA records for the subdomain.
func (p *VercelProvider) DeleteRecords(ctx context.Context, subdomain string, ipv6 bool) error {
	recordType := "A"
	if ipv6 {
		recordType = "AAAA"
	}

	// List existing records
	records, err := p.listRecords(ctx)
	if err != nil {
		return err
	}

	// Filter and delete matching records
	for _, rec := range records {
		if rec.Type == recordType && rec.Name == subdomain {
			if err := p.deleteRecord(ctx, rec.ID); err != nil {
				return fmt.Errorf("delete record %s: %w", rec.ID, err)
			}
		}
	}
	return nil
}

// CreateRecords creates A/AAAA records for the given IPs.
func (p *VercelProvider) CreateRecords(ctx context.Context, subdomain string, ips []netip.Addr) error {
	for _, ip := range ips {
		recordType := "A"
		if ip.Is6() {
			recordType = "AAAA"
		}
		if err := p.createRecord(ctx, subdomain, recordType, ip.String()); err != nil {
			return fmt.Errorf("create record for %s: %w", ip.String(), err)
		}
	}
	return nil
}

func (p *VercelProvider) buildURL(path string) string {
	u := vercelAPIBase + path
	if p.teamID != "" {
		if strings.Contains(u, "?") {
			u += "&teamId=" + url.QueryEscape(p.teamID)
		} else {
			u += "?teamId=" + url.QueryEscape(p.teamID)
		}
	}
	return u
}

func (p *VercelProvider) listRecords(ctx context.Context) ([]vercelDNSRecord, error) {
	path := fmt.Sprintf("/v4/domains/%s/records", url.PathEscape(p.domain))
	reqURL := p.buildURL(path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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

	if resp.StatusCode >= 400 {
		var errResp vercelErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("vercel API error: %s", errResp.Error.Message)
		}
		return nil, fmt.Errorf("vercel API error: status %d", resp.StatusCode)
	}

	var result vercelListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return result.Records, nil
}

func (p *VercelProvider) deleteRecord(ctx context.Context, recordID string) error {
	path := fmt.Sprintf("/v2/domains/%s/records/%s", url.PathEscape(p.domain), url.PathEscape(recordID))
	reqURL := p.buildURL(path)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
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

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var errResp vercelErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return fmt.Errorf("vercel API error: %s", errResp.Error.Message)
		}
		return fmt.Errorf("vercel API error: status %d", resp.StatusCode)
	}

	return nil
}

func (p *VercelProvider) createRecord(ctx context.Context, name, recordType, value string) error {
	path := fmt.Sprintf("/v2/domains/%s/records", url.PathEscape(p.domain))
	reqURL := p.buildURL(path)

	payload := map[string]interface{}{
		"name":  name,
		"type":  recordType,
		"value": value,
		"ttl":   60,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
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

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var errResp vercelErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return fmt.Errorf("vercel API error: %s", errResp.Error.Message)
		}
		return fmt.Errorf("vercel API error: status %d", resp.StatusCode)
	}

	return nil
}
