package connectors

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

func NewOPNSenseBaseConnector(cfg config.OPNSenseConnectorCfg) *OPNSenseBaseConnector {
	return &OPNSenseBaseConnector{
		connectorName: cfg.Name,
		Address:       cfg.BaseURL,
		ApiKey:        cfg.APIKey,
		ApiSecret:     cfg.APISecret,
	}
}

type OPNSenseBaseConnector struct {
	connectorName string
	Address       string
	ApiKey        string
	ApiSecret     string
	client        *http.Client
}

func (c *OPNSenseBaseConnector) Name() string {
	return c.connectorName
}

func (c *OPNSenseBaseConnector) ConnectorType() string {
	return config.ConnectorTypeOPNSense
}

func (c *OPNSenseBaseConnector) setupHttpClient() {
	if c.client == nil {
		c.client = &http.Client{}
		c.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
}

func (c *OPNSenseBaseConnector) newReqWithAuth(ctx context.Context, method, endpoint string) (*http.Request, error) {
	targetPath := c.Address + endpoint
	slog.InfoContext(ctx, "Creating new request", "method", method, "path", targetPath)
	req, err := http.NewRequestWithContext(ctx, method, targetPath, nil)
	if err != nil {
		slog.ErrorContext(ctx, "error creating request", "err", err)
		return nil, err
	}
	req.SetBasicAuth(c.ApiKey, c.ApiSecret)
	return req, nil
}

func (c *OPNSenseBaseConnector) ExecuteGetRequest(ctx context.Context, endpoint string) (string, error) {
	c.setupHttpClient()
	req, err := c.newReqWithAuth(ctx, http.MethodGet, endpoint)
	if err != nil {
		slog.ErrorContext(ctx, "Error creating GET request", "error", err)
		return "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "Error executing GET request", "error", err)
		return "", err
	}

	bd := resp.Body
	defer bd.Close()
	buf := bytes.NewBuffer([]byte{})
	_, err = buf.ReadFrom(bd)
	if err != nil {
		slog.ErrorContext(ctx, "Error reading response body", "error", err)
		return "", err
	}

	slog.InfoContext(ctx, "GET request executed", "status", resp.Status)
	return buf.String(), nil
}

func (c *OPNSenseBaseConnector) ExecutePostRequest(ctx context.Context, endpoint string, body []byte) (string, error) {
	c.setupHttpClient()
	targetPath := c.Address + endpoint
	slog.InfoContext(ctx, "Creating new request", "method", http.MethodPost, "path", targetPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetPath, bytes.NewReader(body))
	if err != nil {
		slog.ErrorContext(ctx, "error creating request", "err", err)
		return "", err
	}
	req.SetBasicAuth(c.ApiKey, c.ApiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "Error executing POST request", "error", err)
		return "", err
	}

	bd := resp.Body
	defer bd.Close()
	buf := bytes.NewBuffer([]byte{})
	_, err = buf.ReadFrom(bd)
	if err != nil {
		slog.ErrorContext(ctx, "Error reading response body", "error", err)
		return "", err
	}

	slog.InfoContext(ctx, "POST request executed", "status", resp.Status)
	return buf.String(), nil
}

// aliasUtilListResponse mirrors the response of OPNsense's
// /api/firewall/alias_util/list/{alias} endpoint, which reports the alias'
// current runtime table content.
type aliasUtilListResponse struct {
	Rows []struct {
		IP string `json:"ip"`
	} `json:"rows"`
}

func (c *OPNSenseBaseConnector) IsValueInAlias(ctx context.Context, aliasID, value string) (bool, error) {
	body, err := c.ExecuteGetRequest(ctx, "/api/firewall/alias_util/list/"+url.PathEscape(aliasID))
	if err != nil {
		return false, err
	}

	var listResp aliasUtilListResponse
	if err := json.Unmarshal([]byte(body), &listResp); err != nil {
		slog.ErrorContext(ctx, "Error decoding alias list response", "error", err)
		return false, err
	}

	for _, row := range listResp.Rows {
		if row.IP == value {
			return true, nil
		}
	}
	return false, nil
}

func (c *OPNSenseBaseConnector) AddValueToAlias(ctx context.Context, aliasID, value string) error {
	body, err := json.Marshal(map[string]string{"address": value})
	if err != nil {
		return err
	}
	_, err = c.ExecutePostRequest(ctx, "/api/firewall/alias_util/add/"+url.PathEscape(aliasID), body)
	return err
}

func (c *OPNSenseBaseConnector) RemoveValueFromAlias(ctx context.Context, aliasID, value string) error {
	body, err := json.Marshal(map[string]string{"address": value})
	if err != nil {
		return err
	}
	_, err = c.ExecutePostRequest(ctx, "/api/firewall/alias_util/delete/"+url.PathEscape(aliasID), body)
	return err
}
