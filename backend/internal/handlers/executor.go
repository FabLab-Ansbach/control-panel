package handlers

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/FabLab-Ansbach/control-panel/internal/executors"
)

func GetExecutorRouter(execs map[string]executors.Executor) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", listHandler(execs))
	mux.HandleFunc("GET /{name}", itemHandler(execs))
	mux.HandleFunc("POST /{name}/execute", executeHandler(execs))

	return mux
}

func listHandler(execs map[string]executors.Executor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		names := make([]string, 0, len(execs))
		for name := range execs {
			names = append(names, name)
		}
		sort.Strings(names)

		results := make([]executorResult, 0, len(names))
		for _, name := range names {
			e := execs[name]
			state, err := e.Status(r.Context())
			results = append(results, executorResultFor(e, state, err))
		}

		writeJSON(w, http.StatusOK, results)
	}
}

func itemHandler(execs map[string]executors.Executor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, ok := execs[r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}

		state, err := e.Status(r.Context())
		writeExecutorResult(w, e, state, err)
	}
}

func executeHandler(execs map[string]executors.Executor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, ok := execs[r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}

		state, err := e.Execute(r.Context())
		writeExecutorResult(w, e, state, err)
	}
}

type executorResult struct {
	Name          string `json:"name"`
	ConnectorName string `json:"connectorName"`
	ConnectorType string `json:"connectorType"`
	State         *bool  `json:"state,omitempty"`
	Error         string `json:"error,omitempty"`
}

func executorResultFor(e executors.Executor, state bool, err error) executorResult {
	conn := e.Connector()
	result := executorResult{
		Name:          e.Name(),
		ConnectorName: conn.Name(),
		ConnectorType: conn.ConnectorType(),
	}
	if err != nil {
		result.Error = err.Error()
	} else {
		result.State = &state
	}
	return result
}

func writeExecutorResult(w http.ResponseWriter, e executors.Executor, state bool, err error) {
	result := executorResultFor(e, state, err)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
