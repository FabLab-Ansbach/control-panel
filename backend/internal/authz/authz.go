package authz

import "github.com/FabLab-Ansbach/control-panel/internal/config"

// Allowed reports whether any of the given groups grants at least `level`
// access to the named executor.
func Allowed(cfg config.PermissionsConfig, groups []string, executor string, level config.AccessLevel) bool {
	for _, group := range groups {
		permission, ok := cfg[group]
		if !ok {
			continue
		}
		if permission.Root {
			return true
		}
		if granted, ok := permission.Executors[executor]; ok && satisfies(granted, level) {
			return true
		}
	}
	return false
}

func satisfies(granted, required config.AccessLevel) bool {
	if granted == config.AccessLevelRW {
		return true
	}
	return granted == required
}
