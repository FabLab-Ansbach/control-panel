package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOPNSenseAliasIsValueInAlias(t *testing.T) {
	present := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	present = true
	got, err = c.IsValueInAlias(ctx, "blocklist", "1.2.3.4")
	if err != nil || got != true {
		t.Fatalf("IsValueInAlias() = %v, %v; want true, nil", got, err)
	}
}

// A non-2xx response (e.g. an expired/invalid API key) must be surfaced as
// an error, not silently parsed as "value not present" - that's exactly
// what made a toggled-on executor look like it "reverted": the periodic
// status poll hit an auth error from OPNsense and, because the old code
// never checked the status code, reported it as a clean "off" instead.
func TestOPNSenseAliasRejectsNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Invalid or expired session"}`))
	}))
	defer srv.Close()

	c := &OPNSenseBaseConnector{Address: srv.URL, ApiKey: "k", ApiSecret: "s"}
	ctx := context.Background()

	if _, err := c.IsValueInAlias(ctx, "blocklist", "1.2.3.4"); err == nil {
		t.Fatal("IsValueInAlias() with a 401 response should return an error, not a silent false")
	}
	if err := c.SetAliasContent(ctx, "blocklist", []string{"1.2.3.4"}); err == nil {
		t.Fatal("SetAliasContent() with a 401 response should return an error")
	}
}

// TestOPNSenseAliasSetContent covers the write path used by the toggler:
// look up the alias' UUID, replace its whole content in one request, then
// apply with one reconfigure - never alias_util's per-address add/delete,
// which choked on more than a couple of values (see git history: batching
// several addresses into one alias_util call got silently rejected by its
// address regex, and doing one alias_util call per address took long
// enough, per value, to blow past the reverse-proxy timeout on an 18-entry
// list and leave the alias half-updated).
func TestOPNSenseAliasSetContent(t *testing.T) {
	var setBody map[string]any
	var reconfigureCalled bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/firewall/alias/getAliasUUID/blocklist":
			json.NewEncoder(w).Encode(map[string]string{"uuid": "abc-123"})
		case r.URL.Path == "/api/firewall/alias/setItem/abc-123":
			json.NewDecoder(r.Body).Decode(&setBody)
			json.NewEncoder(w).Encode(map[string]string{"result": "saved"})
		case r.URL.Path == "/api/firewall/alias/reconfigure":
			reconfigureCalled = true
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := &OPNSenseBaseConnector{Address: srv.URL, ApiKey: "k", ApiSecret: "s"}
	ctx := context.Background()

	if err := c.SetAliasContent(ctx, "blocklist", []string{"10.0.0.5", "10.1.0.0/24"}); err != nil {
		t.Fatalf("SetAliasContent() error: %v", err)
	}

	alias, _ := setBody["alias"].(map[string]any)
	if alias["content"] != "10.0.0.5\n10.1.0.0/24" {
		t.Fatalf("unexpected content posted to setItem: %v", setBody)
	}
	if !reconfigureCalled {
		t.Fatal("expected reconfigure to be called after setItem")
	}
}

// OPNsense's alias/setItem endpoint replies 200 OK even when the change was
// rejected (e.g. {"result":"failed","validations":{...}}) - the "result"
// field, not the HTTP status code, says whether it actually saved.
func TestOPNSenseAliasSetContentRejectsFailedResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/firewall/alias/getAliasUUID/blocklist":
			json.NewEncoder(w).Encode(map[string]string{"uuid": "abc-123"})
		case r.URL.Path == "/api/firewall/alias/setItem/abc-123":
			json.NewEncoder(w).Encode(map[string]any{"result": "failed", "validations": map[string]string{"alias.content": "invalid address"}})
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := &OPNSenseBaseConnector{Address: srv.URL, ApiKey: "k", ApiSecret: "s"}
	ctx := context.Background()

	if err := c.SetAliasContent(ctx, "blocklist", []string{"not-an-address"}); err == nil {
		t.Fatal("SetAliasContent() with a failed result should return an error")
	}
}

// getAliasUUID returns {} (no "uuid" key) for an alias name OPNsense
// doesn't know about - that must surface as an error, not silently proceed
// with an empty UUID.
func TestOPNSenseAliasSetContentRejectsUnknownAlias(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &OPNSenseBaseConnector{Address: srv.URL, ApiKey: "k", ApiSecret: "s"}
	ctx := context.Background()

	if err := c.SetAliasContent(ctx, "nonexistent", []string{"1.2.3.4"}); err == nil {
		t.Fatal("SetAliasContent() for an unknown alias should return an error")
	}
}
