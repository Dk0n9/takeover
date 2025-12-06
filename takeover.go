package takeover

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/miekg/dns"
)

// TakeHandler is a plugin for detecting domain expiration and subdomain takeover vulnerabilities.
type TakeHandler struct {
	Next plugin.Handler
	// Config holds the plugin configuration
	Config *Config
}

// WebhookType represents the type of webhook service
type WebhookType string

const (
	// WebhookTypeDingTalk represents DingTalk webhook
	WebhookTypeDingTalk WebhookType = "dingtalk"
	// WebhookTypeFeishu represents Feishu webhook
	WebhookTypeFeishu WebhookType = "feishu"
)

// Config holds the configuration for the TakeHandler plugin.
type Config struct {
	// CheckResolved enables domain expiration checking
	CheckResolved bool
	// CheckTakeover enables subdomain takeover checking
	CheckTakeover bool
	// CacheTTL defines how long to cache check results
	CacheTTL time.Duration
	// WebhookURL is the URL to send notifications to
	WebhookURL string
	// WebhookType is the type of webhook service
	WebhookType WebhookType
	// takeoverCheckers holds the list of takeover checkers
	takeoverCheckers []Checker
}

// Checker defines the interface for subdomain takeover checkers.
type Checker interface {
	// Name returns the name of the checker
	Name() string
	// Check checks if a subdomain is vulnerable to takeover
	Check(domain string) (bool, string, error)
}

// cacheEntry holds the cached result of a domain check.
type cacheEntry struct {
	// ResolvedCheckResult holds the result of the resolved check
	ResolvedCheckResult *ResolvedCheckResult
	// TakeoverCheckResult holds the result of the takeover check
	TakeoverCheckResult *CheckResult
	// ExpiresAt defines when the cache entry expires
	ExpiresAt time.Time
}

// ResolvedCheckResult holds the result of a domain expiration check.
type ResolvedCheckResult struct {
	// IsResolved indicates if the domain is resolved
	IsResolved bool
	// PointTo indicates the IP address the domain points to
	PointTo string
	// IsWarning indicates if the domain is approaching expiration
	IsWarning bool
}

// CheckResult holds the result of a subdomain takeover check.
type CheckResult struct {
	// IsVulnerable indicates if the subdomain is vulnerable to takeover
	IsVulnerable bool
	// VulnerabilityType indicates the type of vulnerability
	VulnerabilityType string
	// Details provides additional details about the vulnerability
	Details string
}

// cache holds the cached results of domain checks.
var cache = make(map[string]cacheEntry)

// Name implements the TakeHandler interface.
func (th TakeHandler) Name() string {
	return "takeover"
}

// ServeDNS implements the TakeHandler interface.
func (th TakeHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Create a non-writer to capture the response from the next plugin
	nw := nonwriter.New(w)
	// Call the next plugin in the chain
	rcode, err := plugin.NextOrFailure(th.Name(), th.Next, ctx, nw, r)
	if err != nil {
		fmt.Printf("Rcode: %d Error: %s\n", rcode, err)
		return rcode, err
	}

	// Get the domain from the request
	domain := r.Question[0].Name
	domain = strings.TrimSuffix(domain, ".")

	// Process the response
	resp := nw.Msg

	// Check if we need to add domain check results
	if th.Config.CheckResolved || th.Config.CheckTakeover {
		// Get cached result or perform new checks
		cacheKey := fmt.Sprintf("%s|%t|%t", domain, th.Config.CheckResolved, th.Config.CheckTakeover)
		entry, found := cache[cacheKey]
		currentTime := time.Now()

		if !found || entry.ExpiresAt.Before(currentTime) {
			// Instead of performing checks synchronously, we'll:
			// 1. Return a default response immediately
			// 2. Perform checks asynchronously in the background
			// 3. Update the cache with actual results for future requests

			// Create a temporary entry with default values while we perform background checks
			tempEntry := cacheEntry{
				ResolvedCheckResult: &ResolvedCheckResult{},
				TakeoverCheckResult: &CheckResult{},
				ExpiresAt:           currentTime.Add(th.Config.CacheTTL),
			}

			// Cache the temporary entry immediately to prevent duplicate background checks
			cache[cacheKey] = tempEntry

			// Perform checks asynchronously, passing the DNS response
			go th.performAsyncChecks(domain, cacheKey, resp)

			// Use the temporary entry for this request
			entry = tempEntry
		}

		// Send webhook notification if a problem is detected
		if (entry.ResolvedCheckResult != nil && (entry.ResolvedCheckResult.IsResolved || entry.ResolvedCheckResult.IsWarning)) ||
			(entry.TakeoverCheckResult != nil && entry.TakeoverCheckResult.IsVulnerable) {
			go th.sendWebhookNotification(domain, entry.ResolvedCheckResult, entry.TakeoverCheckResult)
		}
	}

	// Write the modified response
	w.WriteMsg(resp)
	return rcode, nil
}

// checkDomainResolved checks if a domain is resolved.
func (th TakeHandler) checkDomainResolved(domain string, resp *dns.Msg) *ResolvedCheckResult {
	// This is a simplified implementation. In a real plugin, you would query WHOIS or use a domain expiration API.
	// For this example, we'll return mock data.
	result := &ResolvedCheckResult{
		IsResolved: true,
		PointTo:    "", // Set point-to to empty string
		IsWarning:  false,
	}

	// Check if the domain resolves using the DNS response if available
	if resp != nil && len(resp.Answer) > 0 {
		result.PointTo = resp.Answer[0].String() // Set point-to to the first answer
		isAvailable, err := th.checkDomainAvailability(domain)
		if err == nil && isAvailable {
			// Domain is resolved but available for purchase - potential issue
			result.IsWarning = true
		}
	} else {
		result.IsResolved = false
		result.IsWarning = true
		return result
	}
	return result
}

// checkDomainAvailability checks if a domain is available for purchase using Aliyun API
func (th TakeHandler) checkDomainAvailability(domain string) (bool, error) {
	// Construct the Aliyun API URL
	// Note: This is a simplified implementation. In production, you would need to handle authentication properly.
	url := fmt.Sprintf("https://checkapi.aliyun.com/check/checkdomain?domain=%s&command=&token=Y3d83b57bc8aca0f156381976a6171f4a&ua=&currency=&site=&bid=&_csrf_token=", domain)

	// Make HTTP request to Aliyun API
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to check domain availability: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	bodyStr := string(body)
	isAvailable := strings.Contains(bodyStr, "avail\":1")
	return isAvailable, nil
}

// checkSubdomainTakeover checks if a subdomain is vulnerable to takeover.
// If a DNS response is provided, it extracts IP addresses from it.
// Otherwise, it performs a fresh DNS lookup.
func (th TakeHandler) checkSubdomainTakeover(domain string, resp *dns.Msg) *CheckResult {
	var ips []net.IP
	var cnames []string

	// Extract IPs from the DNS response if available
	if resp != nil {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A)
			}
			if cname, ok := ans.(*dns.CNAME); ok {
				cnames = append(cnames, cname.Target)
			}
		}
	}

	// Check each IP for known vulnerable patterns
	for _, ip := range ips {
		// Check if IP is 0.0.0.0 (common for unconfigured subdomains)
		if ip.String() == "0.0.0.0" {
			return &CheckResult{
				IsVulnerable:      true,
				VulnerabilityType: "zero_ip",
				Details:           "Subdomain resolves to 0.0.0.0",
			}
		}
	}

	// Check using registered takeover checkers
	for _, checker := range th.Config.takeoverCheckers {
		for _, name := range cnames {
			vulnerable, details, err := checker.Check(name)
			if err == nil && vulnerable {
				return &CheckResult{
					IsVulnerable:      true,
					VulnerabilityType: checker.Name(),
					Details:           details,
				}
			}
		}
	}

	return &CheckResult{
		IsVulnerable:      false,
		VulnerabilityType: "",
		Details:           "",
	}
}

// AWSChecker checks for AWS-related subdomain takeover vulnerabilities.
type AWSChecker struct{}

// Name returns the name of the checker.
func (c *AWSChecker) Name() string {
	return "aws"
}

// Check checks if a subdomain is vulnerable to AWS takeover.
func (c *AWSChecker) Check(domain string) (bool, string, error) {
	if strings.Contains(domain, ".amazonaws.com") || strings.Contains(domain, "s3.") {
		return true, "Potential AWS S3 bucket takeover", nil
	}
	return false, "", nil
}

// AzureChecker checks for Azure-related subdomain takeover vulnerabilities.
type AzureChecker struct{}

// Name returns the name of the checker.
func (c *AzureChecker) Name() string {
	return "azure"
}

// Check checks if a subdomain is vulnerable to Azure takeover.
func (c *AzureChecker) Check(domain string) (bool, string, error) {
	// Check for Azure Web Apps takeover
	if strings.Contains(domain, "azurewebsites.net") {
		return true, "Potential Azure Web Apps takeover", nil
	}
	return false, "", nil
}

// CloudflareChecker checks for Cloudflare-related subdomain takeover vulnerabilities.
type CloudflareChecker struct{}

// Name returns the name of the checker.
func (c *CloudflareChecker) Name() string {
	return "cloudflare"
}

// Check checks if a subdomain is vulnerable to Cloudflare takeover.
func (c *CloudflareChecker) Check(domain string) (bool, string, error) {
	// Check for Cloudflare Workers or Pages takeover
	if strings.Contains(domain, "workers.dev") || strings.Contains(domain, "pages.dev") {
		return true, "Potential Cloudflare Workers/Pages takeover", nil
	}
	return false, "", nil
}

// GitHubPagesChecker checks for GitHub Pages-related subdomain takeover vulnerabilities.
type GitHubPagesChecker struct{}

// Name returns the name of the checker.
func (c *GitHubPagesChecker) Name() string {
	return "github_pages"
}

// Check checks if a subdomain is vulnerable to GitHub Pages takeover.
func (c *GitHubPagesChecker) Check(domain string) (bool, string, error) {
	// Check for GitHub Pages takeover
	if strings.Contains(domain, "github.io") {
		return true, "Potential GitHub Pages takeover", nil
	}
	return false, "", nil
}

// sendWebhookNotification sends a notification to the configured webhook URL.
func (th TakeHandler) sendWebhookNotification(domain string, resolvedResult *ResolvedCheckResult, takeoverResult *CheckResult) error {
	// If no webhook URL is configured, do nothing
	if th.Config.WebhookURL == "" {
		return nil
	}

	// Format payload based on webhook type
	var jsonPayload []byte
	var err error

	switch th.Config.WebhookType {
	case WebhookTypeDingTalk:
		jsonPayload, err = th.formatDingTalkPayload(domain, resolvedResult, takeoverResult)
	case WebhookTypeFeishu:
		jsonPayload, err = th.formatFeishuPayload(domain, resolvedResult, takeoverResult)
	default:
		// Generic webhook (original format)
		jsonPayload, err = th.formatGenericPayload(domain, resolvedResult, takeoverResult)
	}

	if err != nil {
		return fmt.Errorf("failed to format webhook payload: %w", err)
	}

	// Send POST request to webhook URL
	resp, err := http.Post(th.Config.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send webhook notification: %w", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook request failed with status code: %d", resp.StatusCode)
	}

	return nil
}

// formatGenericPayload formats the payload for generic webhooks
func (th TakeHandler) formatGenericPayload(domain string, resolvedResult *ResolvedCheckResult, takeoverResult *CheckResult) ([]byte, error) {
	// Prepare the notification payload
	payload := map[string]interface{}{
		"domain":    domain,
		"timestamp": time.Now().UTC(),
	}

	// Add resolved information if available
	if resolvedResult != nil {
		payload["resolved_check"] = map[string]interface{}{
			"is_resolved": resolvedResult.IsResolved,
			"point_to":    resolvedResult.PointTo,
			"is_warning":  resolvedResult.IsWarning,
		}
	}

	// Add takeover information if available
	if takeoverResult != nil {
		payload["takeover_check"] = map[string]interface{}{
			"is_vulnerable":      takeoverResult.IsVulnerable,
			"vulnerability_type": takeoverResult.VulnerabilityType,
			"details":            takeoverResult.Details,
		}
	}

	// Convert payload to JSON
	return json.Marshal(payload)
}

// formatDingTalkPayload formats the payload for DingTalk webhooks
func (th TakeHandler) formatDingTalkPayload(domain string, resolvedResult *ResolvedCheckResult, takeoverResult *CheckResult) ([]byte, error) {
	// Build message content
	content := fmt.Sprintf("Domain Takeover Alert\nDomain: %s\nTime: %s\n", domain, time.Now().Format(time.RFC3339))

	// Add resolved information if available
	if resolvedResult != nil {
		if resolvedResult.IsWarning {
			content += "Takeover Warning: Domain may be unresolve\n"
		}
	}

	// Add takeover information if available
	if takeoverResult != nil && takeoverResult.IsVulnerable {
		content += fmt.Sprintf("Takeover Vulnerability Detected!\nType: %s\nDetails: %s\n",
			takeoverResult.VulnerabilityType, takeoverResult.Details)
	}

	// Prepare DingTalk webhook payload
	payload := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": content,
		},
	}

	// Convert payload to JSON
	return json.Marshal(payload)
}

// formatFeishuPayload formats the payload for Feishu webhooks
func (th TakeHandler) formatFeishuPayload(domain string, resolvedResult *ResolvedCheckResult, takeoverResult *CheckResult) ([]byte, error) {
	// Build message content
	content := fmt.Sprintf("Domain Takeover Alert\nDomain: %s\nTime: %s\n", domain, time.Now().Format(time.RFC3339))

	// Add resolved information if available
	if resolvedResult != nil {
		if resolvedResult.IsWarning {
			content += "Takeover Warning: Domain may be unresolve\n"
		}
	}

	// Add takeover information if available
	if takeoverResult != nil && takeoverResult.IsVulnerable {
		content += fmt.Sprintf("Takeover Vulnerability Detected!\nType: %s\nDetails: %s\n",
			takeoverResult.VulnerabilityType, takeoverResult.Details)
	}

	// Prepare Feishu webhook payload
	payload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": content,
		},
	}

	// Convert payload to JSON
	return json.Marshal(payload)
}

// performAsyncChecks performs domain expiration and takeover checks in the background
func (th TakeHandler) performAsyncChecks(domain, cacheKey string, resp *dns.Msg) {
	// Perform new checks
	entry := cacheEntry{
		ExpiresAt: time.Now().Add(th.Config.CacheTTL),
	}

	if th.Config.CheckResolved {
		entry.ResolvedCheckResult = th.checkDomainResolved(domain, resp)
	}

	if th.Config.CheckTakeover {
		entry.TakeoverCheckResult = th.checkSubdomainTakeover(domain, resp)
	}

	// Update the cache with actual results
	cache[cacheKey] = entry

	// Send webhook notification if a problem is detected
	if (entry.ResolvedCheckResult != nil && (entry.ResolvedCheckResult.IsResolved || entry.ResolvedCheckResult.IsWarning)) ||
		(entry.TakeoverCheckResult != nil && entry.TakeoverCheckResult.IsVulnerable) {
		go th.sendWebhookNotification(domain, entry.ResolvedCheckResult, entry.TakeoverCheckResult)
	}
}
