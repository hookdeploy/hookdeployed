package enroll

import (
	"bytes"
	"encoding/json"
	"errors"
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
	SessionID       string `json:"session_id"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

type Minted struct {
	Certificate  string `json:"certificate"`
	CA           string `json:"ca"`
	CertChain    string `json:"certChain"`
	Root         string `json:"root"`
	AgentID      string `json:"agent_id"`
	OrgID        string `json:"org_id"`
	OrgName      string `json:"org_name"`
	OrgSlug      string `json:"org_slug"`
	RenewalToken string `json:"renewal_token"`
}

type PollResponse struct {
	Status   string `json:"status"`
	Interval int    `json:"interval"`
	AgentID  string `json:"agent_id"`
	OrgID    string `json:"org_id"`
	Minted
}

type APIError struct {
	Status            int
	Code              string
	Message           string
	AttemptsRemaining int
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func IsInvalidCode(err error) bool {
	var api *APIError
	return errors.As(err, &api) && api.Code == "invalid_code"
}

type TokenResponse struct {
	Status  string `json:"status"`
	AgentID string `json:"agent_id"`
	OrgID   string `json:"org_id"`
	Minted
}

func (c *Client) DeviceStart(hostname string) (*StartResponse, error) {
	body := map[string]string{}
	if hostname != "" {
		body["hostname"] = hostname
	}
	var out StartResponse
	if err := c.post("/v1/enroll/device/start", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DevicePoll(deviceCode, userCode string, csrPEM []byte) (*PollResponse, error) {
	body := map[string]string{"device_code": deviceCode}
	if userCode != "" {
		body["user_code"] = userCode
	}
	if len(csrPEM) > 0 {
		body["csr"] = string(csrPEM)
	}
	var out PollResponse
	if err := c.post("/v1/enroll/device/poll", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TokenStart(token, hostname string) (*TokenResponse, error) {
	body := map[string]string{"token": token}
	if hostname != "" {
		body["hostname"] = hostname
	}
	var out TokenResponse
	if err := c.post("/v1/enroll/token", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TokenComplete(token string, csrPEM []byte, hostname string) (*TokenResponse, error) {
	body := map[string]string{
		"token": token,
		"csr":   string(csrPEM),
	}
	if hostname != "" {
		body["hostname"] = hostname
	}
	var out TokenResponse
	if err := c.post("/v1/enroll/token", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Renew(certificatePEM, intermediatePEM, rootPEM, csrPEM []byte) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.post("/v1/enroll/renew", map[string]string{
		"certificate": string(certificatePEM),
		"ca":          string(intermediatePEM),
		"root":        string(rootPEM),
		"csr":         string(csrPEM),
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RenewWithToken(renewalToken string, csrPEM []byte) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.post("/v1/enroll/renew", map[string]string{
		"renewal_token": renewalToken,
		"csr":           string(csrPEM),
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
		var parsed struct {
			Error             string `json:"error"`
			Message           string `json:"message"`
			AttemptsRemaining int    `json:"attempts_remaining"`
		}
		if json.Unmarshal(payload, &parsed) == nil && parsed.Error != "" {
			return &APIError{
				Status:            resp.StatusCode,
				Code:              parsed.Error,
				Message:           parsed.Message,
				AttemptsRemaining: parsed.AttemptsRemaining,
			}
		}
		return fmt.Errorf("enroll %s: %s: %s", path, resp.Status, payload)
	}
	return json.Unmarshal(payload, dest)
}
