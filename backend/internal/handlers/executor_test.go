package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FabLab-Ansbach/control-panel/internal/authn"
	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/FabLab-Ansbach/control-panel/internal/executors"
)

type fakeConn struct{}

func (fakeConn) Name() string          { return "fake-conn" }
func (fakeConn) ConnectorType() string { return "fake" }

type fakeExec struct{ name string }

func (e fakeExec) Execute(ctx context.Context) (bool, error) { return true, nil }
func (e fakeExec) Status(ctx context.Context) (bool, error)  { return false, nil }
func (e fakeExec) Name() string                              { return e.name }
func (e fakeExec) Connector() connectors.Connector           { return fakeConn{} }

func testRouter() http.Handler {
	execs := map[string]executors.Executor{
		"visible":  fakeExec{name: "visible"},
		"hidden":   fakeExec{name: "hidden"},
		"readOnly": fakeExec{name: "readOnly"},
	}
	perms := config.PermissionsConfig{
		"members": {Executors: map[string]config.AccessLevel{
			"visible":  config.AccessLevelRW,
			"readOnly": config.AccessLevelRO,
		}},
	}
	return GetExecutorRouter(execs, perms)
}

func withGroups(req *http.Request, groups []string) *http.Request {
	return req.WithContext(authn.WithGroups(req.Context(), groups))
}

func TestListFiltersToVisibleExecutors(t *testing.T) {
	req := withGroups(httptest.NewRequest(http.MethodGet, "/", nil), []string{"members"})
	rec := httptest.NewRecorder()
	testRouter().ServeHTTP(rec, req)

	var results []executorResult
	if err := json.NewDecoder(rec.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d executors, want 2 (hidden one must not appear): %+v", len(results), results)
	}
	for _, r := range results {
		if r.Name == "hidden" {
			t.Fatalf("hidden executor leaked into list: %+v", results)
		}
	}
}

func TestExecuteRequiresRW(t *testing.T) {
	cases := []struct {
		name       string
		executor   string
		groups     []string
		wantStatus int
	}{
		{"rw group may execute", "visible", []string{"members"}, http.StatusOK},
		{"ro group may not execute", "readOnly", []string{"members"}, http.StatusForbidden},
		{"unlisted executor forbidden", "hidden", []string{"members"}, http.StatusForbidden},
		{"unknown group forbidden", "visible", []string{"strangers"}, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := withGroups(httptest.NewRequest(http.MethodPost, "/"+tc.executor+"/execute", nil), tc.groups)
			rec := httptest.NewRecorder()
			testRouter().ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestItemRequiresRO(t *testing.T) {
	req := withGroups(httptest.NewRequest(http.MethodGet, "/readOnly", nil), []string{"members"})
	rec := httptest.NewRecorder()
	testRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}
