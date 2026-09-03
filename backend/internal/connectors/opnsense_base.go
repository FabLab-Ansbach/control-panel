package connectors

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("opnsense request to %s failed: %s: %s", endpoint, resp.Status, buf.String())
	}
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("opnsense request to %s failed: %s: %s", endpoint, resp.Status, buf.String())
	}
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

func (c *OPNSenseBaseConnector) listAliasValues(ctx context.Context, aliasID string) (map[string]bool, error) {
	body, err := c.ExecuteGetRequest(ctx, "/api/firewall/alias_util/list/"+url.PathEscape(aliasID))
	if err != nil {
		return nil, err
	}

	var listResp aliasUtilListResponse
	if err := json.Unmarshal([]byte(body), &listResp); err != nil {
		slog.ErrorContext(ctx, "Error decoding alias list response", "error", err)
		return nil, err
	}

	values := make(map[string]bool, len(listResp.Rows))
	for _, row := range listResp.Rows {
		values[row.IP] = true
	}
	return values, nil
}

func (c *OPNSenseBaseConnector) IsValueInAlias(ctx context.Context, aliasID, value string) (bool, error) {
	values, err := c.listAliasValues(ctx, aliasID)
	if err != nil {
		return false, err
	}
	return values[value], nil
}

// ValuesInAlias reports whether every one of values is currently present in
// the alias, using a single list request regardless of how many values are
// checked.
func (c *OPNSenseBaseConnector) ValuesInAlias(ctx context.Context, aliasID string, values []string) (bool, error) {
	present, err := c.listAliasValues(ctx, aliasID)
	if err != nil {
		return false, err
	}
	for _, value := range values {
		if !present[value] {
			return false, nil
		}
	}
	return true, nil
}

// getAliasUUID resolves an alias' config UUID from its name, needed to
// address it through OPNsense's Alias config API (as opposed to alias_util,
// which is keyed by name directly).
func (c *OPNSenseBaseConnector) getAliasUUID(ctx context.Context, aliasName string) (string, error) {
	body, err := c.ExecuteGetRequest(ctx, "/api/firewall/alias/getAliasUUID/"+url.PathEscape(aliasName))
	if err != nil {
		return "", err
	}
	var parsed struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		slog.ErrorContext(ctx, "Error decoding alias UUID response", "error", err)
		return "", err
	}
	if parsed.UUID == "" {
		return "", fmt.Errorf("opnsense alias %q not found", aliasName)
	}
	return parsed.UUID, nil
}

// SetAliasContent replaces an alias' entire member list in one shot: it
// writes all of values as the alias' content, then applies the change with
// a single reconfigure.
//
// Unlike alias_util's add/delete (one request per address, each triggering
// its own template reload - a storm of pf table reloads and, for a list of
// any real size, several times the round-trip latency of a single request,
// enough to blow past a reverse-proxy timeout mid-toggle and leave the
// alias in a half-applied state), this updates the alias' config content
// field directly and reloads once, regardless of how many values are in
// the list.
func (c *OPNSenseBaseConnector) SetAliasContent(ctx context.Context, aliasName string, values []string) error {
	uuid, err := c.getAliasUUID(ctx, aliasName)
	if err != nil {
		return err
	}

	setBody, err := json.Marshal(map[string]any{
		"alias": map[string]string{"content": strings.Join(values, "\n")},
	})
	if err != nil {
		return err
	}
	setResp, err := c.ExecutePostRequest(ctx, "/api/firewall/alias/setItem/"+url.PathEscape(uuid), setBody)
	if err != nil {
		return err
	}
	var setParsed struct {
		Result      string         `json:"result"`
		Validations map[string]any `json:"validations"`
	}
	if err := json.Unmarshal([]byte(setResp), &setParsed); err != nil {
		slog.ErrorContext(ctx, "Error decoding alias setItem response", "error", err)
		return err
	}
	if setParsed.Result != "saved" {
		return fmt.Errorf("opnsense alias/setItem/%s rejected content: %s %v", uuid, setParsed.Result, setParsed.Validations)
	}

	reconfigureResp, err := c.ExecutePostRequest(ctx, "/api/firewall/alias/reconfigure", []byte("{}"))
	if err != nil {
		return err
	}
	var reconfigureParsed struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(reconfigureResp), &reconfigureParsed); err != nil {
		slog.ErrorContext(ctx, "Error decoding alias reconfigure response", "error", err)
		return err
	}
	if reconfigureParsed.Status != "ok" {
		return fmt.Errorf("opnsense alias/reconfigure failed: %s", reconfigureParsed.Status)
	}
	return nil
}
