package handlers

import (
	"net/http"

	"github.com/FabLab-Ansbach/control-panel/internal/authn"
	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/FabLab-Ansbach/control-panel/internal/executors"
	"github.com/FabLab-Ansbach/control-panel/internal/reqlog"
)

func StartAPIServer(cfg config.Config, execs []executors.Executor, conns connectors.Set, auth *authn.Authenticator) error {
	router := GetApiBaseRouter(cfg, execs, conns, auth)
	http.ListenAndServe(":8090", router)
	return nil
}

func GetApiBaseRouter(cfg config.Config, execs []executors.Executor, conns connectors.Set, auth *authn.Authenticator) http.Handler {
	byName := make(map[string]executors.Executor, len(execs))
	for _, e := range execs {
		byName[e.Name()] = newCachedExecutor(e)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", HandleGetHealth)
	mux.HandleFunc("GET /auth/login", auth.LoginHandler)
	mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
	mux.HandleFunc("GET /auth/logout", auth.LogoutHandler)

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
