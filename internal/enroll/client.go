package enroll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type StartResponse struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

type PollResponse struct {
	Status      string `json:"status"`
	Interval    int    `json:"interval"`
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	CertChain   string `json:"certChain"`
	AgentID     string `json:"agent_id"`
	OrgID       string `json:"org_id"`
}

type TokenResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	CertChain   string `json:"certChain"`
	AgentID     string `json:"agent_id"`
	OrgID       string `json:"org_id"`
}

func (c *Client) DeviceStart(csrPEM []byte, orgHint string) (*StartResponse, error) {
	var out StartResponse
	if err := c.post("/v1/enroll/device/start", map[string]string{
		"csr":      string(csrPEM),
		"org_hint": orgHint,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DevicePoll(deviceCode string) (*PollResponse, error) {
	var out PollResponse
	if err := c.post("/v1/enroll/device/poll", map[string]string{
		"device_code": deviceCode,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TokenEnroll(token string, csrPEM []byte) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.post("/v1/enroll/token", map[string]string{
		"token": token,
		"csr":   string(csrPEM),
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Renew(certificatePEM, caPEM, csrPEM []byte) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.post("/v1/enroll/renew", map[string]string{
		"certificate": string(certificatePEM),
		"ca":          string(caPEM),
		"csr":         string(csrPEM),
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) post(path string, body any, dest any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Post(c.BaseURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("enroll %s: %s: %s", path, resp.Status, payload)
	}
	return json.Unmarshal(payload, dest)
}
