package handlers

import (
	"net/http"
	"sort"

	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
)

type connectorInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func GetConnectorRouter(conns connectors.Set) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", connectorListHandler(conns))
	mux.HandleFunc("GET /{name}", connectorItemHandler(conns))

	return mux
}

func connectorListHandler(conns connectors.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		infos := make([]connectorInfo, 0, len(conns))
		for _, c := range conns {
			infos = append(infos, connectorInfo{Name: c.Name(), Type: c.ConnectorType()})
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })

		writeJSON(w, http.StatusOK, infos)
	}
}

func connectorItemHandler(conns connectors.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := conns[r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}

		writeJSON(w, http.StatusOK, connectorInfo{Name: c.Name(), Type: c.ConnectorType()})
	}
}
