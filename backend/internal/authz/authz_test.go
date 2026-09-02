package authz

import (
	"testing"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

func TestAllowed(t *testing.T) {
	cfg := config.PermissionsConfig{
		"admins": {Root: true},
		"members": {Executors: map[string]config.AccessLevel{
			"inetKillswitch": config.AccessLevelRO,
			"guestWifi":      config.AccessLevelRW,
		}},
	}

	cases := []struct {
		name     string
		groups   []string
		executor string
		level    config.AccessLevel
		want     bool
	}{
		{"root bypasses everything", []string{"admins"}, "anything", config.AccessLevelRW, true},
		{"ro satisfies ro", []string{"members"}, "inetKillswitch", config.AccessLevelRO, true},
		{"ro does not satisfy rw", []string{"members"}, "inetKillswitch", config.AccessLevelRW, false},
		{"rw satisfies ro", []string{"members"}, "guestWifi", config.AccessLevelRO, true},
		{"unknown group denied", []string{"nobody"}, "inetKillswitch", config.AccessLevelRO, false},
		{"unlisted executor denied", []string{"members"}, "otherExecutor", config.AccessLevelRO, false},
		{"first group without access, second with", []string{"nobody", "members"}, "guestWifi", config.AccessLevelRW, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Allowed(cfg, tc.groups, tc.executor, tc.level); got != tc.want {
				t.Errorf("Allowed(%v, %q, %q) = %v, want %v", tc.groups, tc.executor, tc.level, got, tc.want)
			}
		})
	}
}
