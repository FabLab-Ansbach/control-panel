// Package reqlog gives every incoming HTTP request a request ID and logs one
// access line per request. The same reqId/method/path/user also get attached
// to every other log call made with that request's context, via Handler.
package reqlog

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type requestInfo struct {
	reqID  string
	method string
	path   string
	user   string // filled in later by auth, once known
}

type requestInfoKey struct{}

// Middleware assigns a request ID to each incoming request and logs one
// access line (method, path, status, duration) after it completes.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := &requestInfo{reqID: newReqID(), method: r.Method, path: r.URL.Path}
		ctx := context.WithValue(r.Context(), requestInfoKey{}, info)

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))

		slog.InfoContext(ctx, "request", "status", sw.status, "duration", time.Since(start))
	})
}

// SetUser records the authenticated principal for the current request, so it
// appears on the access log line and on any other log call made with this
// request's context from here on.
func SetUser(ctx context.Context, user string) {
	if info, ok := ctx.Value(requestInfoKey{}).(*requestInfo); ok {
		info.user = user
	}
}

// Handler wraps a slog.Handler to attach reqId/method/path/user (as set by
// Middleware and SetUser) to every log record made with a request's context.
type Handler struct {
	slog.Handler
}

func (h Handler) Handle(ctx context.Context, record slog.Record) error {
	if info, ok := ctx.Value(requestInfoKey{}).(*requestInfo); ok {
		record.AddAttrs(
			slog.String("reqId", info.reqID),
			slog.String("method", info.method),
			slog.String("path", info.path),
		)
		if info.user != "" {
			record.AddAttrs(slog.String("user", info.user))
		}
	}
	return h.Handler.Handle(ctx, record)
}

func (h Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return Handler{h.Handler.WithAttrs(attrs)}
}

func (h Handler) WithGroup(name string) slog.Handler {
	return Handler{h.Handler.WithGroup(name)}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func newReqID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
