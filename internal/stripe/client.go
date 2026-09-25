// Package stripe is a minimal Stripe REST client for the demo's funding leg: it
// creates a test-mode PaymentIntent and confirms it with a test payment method.
// It deliberately implements only what the ACP seller needs; it is the concrete
// funding rail behind the PaymentPrimitive seam (SPT can replace it later).
package stripe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is Stripe's API root.
const DefaultBaseURL = "https://api.stripe.com"

// Client calls the Stripe REST API with a secret key.
type Client struct {
	secret string
	base   string
	http   *http.Client
}

// NewClient returns a client for the live Stripe API root.
func NewClient(secretKey string) *Client { return NewClientWithBase(secretKey, DefaultBaseURL) }

// NewClientWithBase returns a client pointed at base (used by tests).
func NewClientWithBase(secretKey, base string) *Client {
	return &Client{secret: secretKey, base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 15 * time.Second}}
}

// PaymentIntentRequest is the demo's charge input.
type PaymentIntentRequest struct {
	Amount         int64
	Currency       string
	Description    string
	IdempotencyKey string
	Metadata       map[string]string
}

// PaymentIntent is the subset of the Stripe response the demo uses.
type PaymentIntent struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
		Type    string `json:"type"`
	} `json:"error"`
}

// CreatePaymentIntent creates and confirms a test-mode PaymentIntent using the
// pm_card_visa test payment method. Returns the PaymentIntent id and status.
func (c *Client) CreatePaymentIntent(ctx context.Context, in PaymentIntentRequest) (PaymentIntent, error) {
	form := url.Values{}
	form.Set("amount", strconv.FormatInt(in.Amount, 10))
	form.Set("currency", in.Currency)
	form.Set("payment_method", "pm_card_visa")
	form.Add("payment_method_types[]", "card")
	form.Set("confirm", "true")
	if in.Description != "" {
		form.Set("description", in.Description)
	}
	for k, v := range in.Metadata {
		form.Set("metadata["+k+"]", v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/payment_intents", strings.NewReader(form.Encode()))
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if in.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", in.IdempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return PaymentIntent{}, fmt.Errorf("stripe request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var ae apiError
		if json.Unmarshal(body, &ae) == nil && ae.Error.Message != "" {
			return PaymentIntent{}, fmt.Errorf("stripe: %s (code %s, status %d)", ae.Error.Message, ae.Error.Code, resp.StatusCode)
		}
		return PaymentIntent{}, fmt.Errorf("stripe: unexpected status %d", resp.StatusCode)
	}
	var pi PaymentIntent
	if err := json.Unmarshal(body, &pi); err != nil {
		return PaymentIntent{}, fmt.Errorf("decode payment intent: %w", err)
	}
	if pi.ID == "" {
		return PaymentIntent{}, fmt.Errorf("stripe: empty payment intent id")
	}
	return pi, nil
}
