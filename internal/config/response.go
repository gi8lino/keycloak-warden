package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/containeroo/httpkit/parse"
	"github.com/containeroo/notifykit/response"
	"go.yaml.in/yaml/v4"
)

// WebhookResponse configures optional HTTP acceptance and body validation.
// Without this section, Warden accepts only HTTP 2xx and does not read response bodies.
type WebhookResponse struct {
	// StatusCodes is a comma-separated list of individual HTTP status codes and inclusive ranges.
	// An empty value retains the default HTTP 2xx acceptance rule.
	StatusCodes string `yaml:"status-codes"`
	// Text optionally matches the complete response body or a substring of it.
	Text *WebhookTextResponse `yaml:"text"`
	// JSON optionally matches a typed JSON value and extracts an error message.
	JSON *WebhookJSONResponse `yaml:"json"`
}

// WebhookTextResponse checks exactly one plain-text condition.
type WebhookTextResponse struct {
	// Equals matches the complete response, including empty strings.
	Equals *string `yaml:"equals"`
	// Contains matches a nonempty substring in the response body.
	Contains *string `yaml:"contains"`
}

// WebhookJSONResponse checks one JSON Pointer value and optionally extracts an error.
type WebhookJSONResponse struct {
	// Pointer selects the value to compare; an empty pointer selects the document root.
	Pointer string `yaml:"pointer"`
	// Equals holds the expected typed YAML value, converted to JSON on initialization.
	// A YAML node distinguishes an omitted field from an explicit null value.
	Equals yaml.Node `yaml:"equals"`
	// ErrorPointer selects an optional scalar error value from a failed response.
	ErrorPointer string `yaml:"error-pointer"`
}

// Rule converts YAML configuration into an independent Notifykit response rule.
// Parsing and validation happen at startup, not for individual deliveries.
func (cfg WebhookResponse) Rule() (response.Rule, error) {
	codes, err := parseWebhookStatusCodes(cfg.StatusCodes)
	if err != nil {
		return response.Rule{}, err
	}

	rule := response.Rule{StatusCodes: codes}
	if cfg.Text != nil {
		rule.Text = cfg.Text.toRule()
	}

	if cfg.JSON != nil {
		rule.JSON, err = cfg.JSON.toRule()
		if err != nil {
			return response.Rule{}, err
		}
	}

	if err := rule.Validate(); err != nil {
		return response.Rule{}, err
	}

	return rule.Clone(), nil
}

// parseWebhookStatusCodes converts a bounded HTTPKit status expression into codes.
func parseWebhookStatusCodes(expression string) ([]int, error) {
	if expression == "" {
		return nil, nil
	}

	codes, err := parse.ParseStatusCodes(
		expression,
		parse.WithStatusCodeRange(200, 599),
	)
	if err != nil {
		return nil, fmt.Errorf("status-codes: %w", err)
	}

	return codes, nil
}

// toRule translates a plain-text matcher without interpreting its contents.
func (cfg WebhookTextResponse) toRule() *response.Text {
	return &response.Text{
		Equals:   cfg.Equals,
		Contains: cfg.Contains,
	}
}

// toRule converts the typed YAML expected value to its JSON representation.
func (cfg WebhookJSONResponse) toRule() (*response.JSON, error) {
	if cfg.Equals.Kind == 0 {
		return nil, errors.New("json.equals: expected JSON value is required")
	}

	var expected any
	if err := cfg.Equals.Decode(&expected); err != nil {
		return nil, fmt.Errorf("json.equals: invalid expected value: %w", err)
	}

	encoded, err := json.Marshal(expected)
	if err != nil {
		return nil, fmt.Errorf("json.equals: expected value cannot be converted to JSON: %w", err)
	}

	return &response.JSON{
		Pointer:      cfg.Pointer,
		Equals:       encoded,
		ErrorPointer: cfg.ErrorPointer,
	}, nil
}
