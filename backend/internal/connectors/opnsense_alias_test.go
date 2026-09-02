package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOPNSenseAlias(t *testing.T) {
	var lastMethod, lastPath string
	var lastBody map[string]string
	present := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.Method
		lastPath = r.URL.Path
		if r.Method == http.MethodPost {
			lastBody = map[string]string{}
			json.NewDecoder(r.Body).Decode(&lastBody)
		}
		if r.URL.Path == "/api/firewall/alias_util/list/blocklist" {
			rows := []map[string]string{}
			if present {
				rows = append(rows, map[string]string{"ip": "1.2.3.4"})
			}
			json.NewEncoder(w).Encode(map[string]any{"rows": rows})
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &OPNSenseBaseConnector{Address: srv.URL, ApiKey: "k", ApiSecret: "s"}
	ctx := context.Background()

	got, err := c.IsValueInAlias(ctx, "blocklist", "1.2.3.4")
	if err != nil || got != false {
		t.Fatalf("IsValueInAlias() = %v, %v; want false, nil", got, err)
	}

	if err := c.AddValueToAlias(ctx, "blocklist", "1.2.3.4"); err != nil {
		t.Fatalf("AddValueToAlias() error: %v", err)
	}
	if lastMethod != http.MethodPost || lastPath != "/api/firewall/alias_util/add/blocklist" || lastBody["address"] != "1.2.3.4" {
		t.Fatalf("unexpected add request: %s %s %v", lastMethod, lastPath, lastBody)
	}

	present = true
	got, err = c.IsValueInAlias(ctx, "blocklist", "1.2.3.4")
	if err != nil || got != true {
		t.Fatalf("IsValueInAlias() = %v, %v; want true, nil", got, err)
	}

	if err := c.RemoveValueFromAlias(ctx, "blocklist", "1.2.3.4"); err != nil {
		t.Fatalf("RemoveValueFromAlias() error: %v", err)
	}
	if lastMethod != http.MethodPost || lastPath != "/api/firewall/alias_util/delete/blocklist" || lastBody["address"] != "1.2.3.4" {
		t.Fatalf("unexpected delete request: %s %s %v", lastMethod, lastPath, lastBody)
	}
}
