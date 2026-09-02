package reqlog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewReqIDIsUUIDv4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newReqID()
		if !uuidV4Pattern.MatchString(id) {
			t.Fatalf("newReqID() = %q, not a valid UUIDv4", id)
		}
		if seen[id] {
			t.Fatalf("newReqID() produced a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestMiddlewareLogsReqIDMethodPathStatusAndUser(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(Handler{base})

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetUser(r.Context(), "alice")
		// A handler-level log call should also carry reqId/method/path/user.
		logger.InfoContext(r.Context(), "handling")
		w.WriteHeader(http.StatusTeapot)
	}))

	oldDefault := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldDefault)

	req := httptest.NewRequest(http.MethodPost, "/executors/foo/execute", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2 (handler log + access log): %s", len(lines), buf.String())
	}

	var handlerLog, accessLog map[string]any
	if err := json.Unmarshal(lines[0], &handlerLog); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &accessLog); err != nil {
		t.Fatal(err)
	}

	for _, rec := range []map[string]any{handlerLog, accessLog} {
		if rec["method"] != http.MethodPost {
			t.Errorf("method = %v, want POST: %v", rec["method"], rec)
		}
		if rec["path"] != "/executors/foo/execute" {
			t.Errorf("path = %v, want /executors/foo/execute: %v", rec["path"], rec)
		}
		if rec["user"] != "alice" {
			t.Errorf("user = %v, want alice: %v", rec["user"], rec)
		}
		if rec["reqId"] == "" || rec["reqId"] == nil {
			t.Errorf("reqId missing: %v", rec)
		}
	}
	if handlerLog["reqId"] != accessLog["reqId"] {
		t.Errorf("handler and access log reqId mismatch: %v != %v", handlerLog["reqId"], accessLog["reqId"])
	}
	if got := accessLog["status"]; got != float64(http.StatusTeapot) {
		t.Errorf("status = %v, want %d", got, http.StatusTeapot)
	}
}

func TestSetUserWithoutMiddlewareIsNoop(t *testing.T) {
	// Should not panic when called on a context reqlog.Middleware never set up.
	SetUser(context.Background(), "someone")
}
