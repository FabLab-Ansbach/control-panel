package handlers

import (
	"fmt"
	"net/http"

	"github.com/FabLab-Ansbach/control-panel/internal/authn"
	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/FabLab-Ansbach/control-panel/internal/executors"
	"github.com/FabLab-Ansbach/control-panel/internal/reqlog"
)

const defaultListenPort = 8090

func StartAPIServer(cfg config.Config, execs []executors.Executor, conns connectors.Set, auth *authn.Authenticator) error {
	router := GetApiBaseRouter(cfg, execs, conns, auth)

	port := cfg.ListenPort
	if port == 0 {
		port = defaultListenPort
	}
	return http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenAddr, port), router)
}

func GetApiBaseRouter(cfg config.Config, execs []executors.Executor, conns connectors.Set, auth *authn.Authenticator) http.Handler {
	byName := make(map[string]executors.Executor, len(execs))
	for _, e := range execs {
		byName[e.Name()] = newCachedExecutor(e)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", HandleGetHealth)
	mux.HandleFunc("GET /auth/config", auth.ConfigHandler)
	mux.HandleFunc("POST /auth/token", auth.TokenProxyHandler)

	mux.Handle("/executors/", auth.RequireAuth(http.StripPrefix("/executors", GetExecutorRouter(byName, cfg.Permissions))))
	mux.Handle("/connectors/", auth.RequireAuth(http.StripPrefix("/connectors", GetConnectorRouter(conns))))

	if cfg.FrontendDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(cfg.FrontendDir)))
	}

	return reqlog.Middleware(mux)
}

func HandleGetHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
