package takeover

import (
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	// Register the plugin
	plugin.Register("takeover", setup)
}

// setup is the function that gets called when the plugin is loaded.
func setup(c *caddy.Controller) error {
	// Parse the plugin configuration
	config, err := parseConfig(c)
	if err != nil {
		return err
	}

	// Register the plugin handler
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return TakeHandler{
			Next:   next,
			Config: config,
		}
	})

	return nil
}

// parseConfig parses the plugin configuration from the Corefile.
func parseConfig(c *caddy.Controller) (*Config, error) {
	// Set default configuration values
	config := &Config{
		CheckResolved:    true,
		CheckTakeover:    true,
		CacheTTL:         24 * time.Hour,
		WebhookType:      WebhookTypeDingTalk,
		takeoverCheckers: []Checker{},
	}

	// Add default takeover checkers
	config.takeoverCheckers = append(config.takeoverCheckers,
		&AWSChecker{},
		&AzureChecker{},
		&CloudflareChecker{},
		&GitHubPagesChecker{},
	)

	// Parse Corefile directives
	for c.Next() {
		// Parse any arguments
		args := c.RemainingArgs()
		if len(args) > 0 {
			// No positional arguments expected
			return nil, c.ArgErr()
		}

		// Parse any blocks
		for c.NextBlock() {
			switch c.Val() {
			case "check_resolved":
				// Parse check_expiration directive
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				val := c.Val()
				config.CheckResolved = val == "on" || val == "true" || val == "1"

			case "check_takeover":
				// Parse check_takeover directive
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				val := c.Val()
				config.CheckTakeover = val == "on" || val == "true" || val == "1"

			case "cache_ttl":
				// Parse cache_ttl directive
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				val := c.Val()
				ttl, err := time.ParseDuration(val)
				if err != nil {
					return nil, c.Errf("invalid cache_ttl value: %s", val)
				}
				config.CacheTTL = ttl

			case "webhook_url":
				// Parse webhook_url directive
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				config.WebhookURL = c.Val()

			case "webhook_type":
				// Parse webhook_type directive
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				webhookType := c.Val()
				switch webhookType {
				case "dingtalk", "feishu":
					config.WebhookType = WebhookType(webhookType)
				default:
					return nil, c.Errf("unknown webhook_type: %s", webhookType)
				}

			default:
				// Unknown directive
				return nil, c.Errf("unknown property: %s", c.Val())
			}
		}
	}

	return config, nil
}
