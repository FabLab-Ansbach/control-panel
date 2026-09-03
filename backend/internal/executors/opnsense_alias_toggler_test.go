package executors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
)

// TestOPNSenseAliasTogglerMultiValue verifies that a toggler with several
// values - a host IP and a CIDR network - is toggled as one unit: Status is
// "on" only once every value is present (checked with a single list
// request), and Execute replaces the alias' whole content in one
// getAliasUUID+setItem+reconfigure round trip, not one alias_util request
// per value - that per-value approach is what let a real 18-address toggle
// blow past a reverse-proxy timeout mid-flight and leave the alias
// half-updated.
func TestOPNSenseAliasTogglerMultiValue(t *testing.T) {
	var content string
	var writeRequests int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/firewall/alias_util/list/mixed":
			rows := []map[string]string{}
			if content != "" {
				for _, v := range strings.Split(content, "\n") {
					rows = append(rows, map[string]string{"ip": v})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"rows": rows})
		case r.URL.Path == "/api/firewall/alias/getAliasUUID/mixed":
			writeRequests++
			json.NewEncoder(w).Encode(map[string]string{"uuid": "abc-123"})
		case r.URL.Path == "/api/firewall/alias/setItem/abc-123":
			writeRequests++
			var body struct {
				Alias struct {
					Content string `json:"content"`
				} `json:"alias"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			content = body.Alias.Content
			json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
		case r.URL.Path == "/api/firewall/alias/reconfigure":
			writeRequests++
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	conn := &connectors.OPNSenseBaseConnector{Address: srv.URL, ApiKey: "k", ApiSecret: "s"}
	toggler := NewOPNSenseAliasToggler("mixed-toggle", conn, "mixed", []string{"10.0.0.5", "10.1.0.0/24"})
	ctx := context.Background()

	if state, err := toggler.Status(ctx); err != nil || state != false {
		t.Fatalf("initial Status() = %v, %v; want false, nil", state, err)
	}

	state, err := toggler.Execute(ctx)
	if err != nil || state != true {
		t.Fatalf("Execute() = %v, %v; want true, nil", state, err)
	}
	if writeRequests != 3 {
		t.Fatalf("expected 3 requests (getAliasUUID+setItem+reconfigure) regardless of value count, got %d", writeRequests)
	}
	if content != "10.0.0.5\n10.1.0.0/24" {
		t.Fatalf("unexpected alias content after Execute: %q", content)
	}

	if state, err := toggler.Status(ctx); err != nil || state != true {
		t.Fatalf("Status() after enabling = %v, %v; want true, nil", state, err)
	}

	writeRequests = 0
	state, err = toggler.Execute(ctx)
	if err != nil || state != false {
		t.Fatalf("Execute() = %v, %v; want false, nil", state, err)
	}
	if writeRequests != 3 {
		t.Fatalf("expected 3 requests (getAliasUUID+setItem+reconfigure) to clear the alias, got %d", writeRequests)
	}
	if content != "" {
		t.Fatalf("expected alias content cleared after Execute, got %q", content)
	}
}
