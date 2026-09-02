package handlers

import (
	"net/http"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/FabLab-Ansbach/control-panel/internal/executors"
)

func StartAPIServer(cfg config.Config, execs []executors.Executor, conns connectors.Set) error {
	router := GetApiBaseRouter(execs, conns)
	http.ListenAndServe(":8090", router)
	return nil
}

func GetApiBaseRouter(execs []executors.Executor, conns connectors.Set) http.Handler {
	byName := make(map[string]executors.Executor, len(execs))
	for _, e := range execs {
		byName[e.Name()] = e
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", HandleGetHealth)
	mux.Handle("/executors/", http.StripPrefix("/executors", GetExecutorRouter(byName)))
	mux.Handle("/connectors/", http.StripPrefix("/connectors", GetConnectorRouter(conns)))
	return withCORS(mux)
}

// withCORS allows the browser-based frontend (served from a different origin
// than the API) to read responses.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

func HandleGetHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
