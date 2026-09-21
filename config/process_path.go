package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// expandProcessPaths returns the configured process paths, and on Windows also
// the spelling Windows itself uses on disk.
//
// The router matches process paths with an exact, case-sensitive map lookup
// (route/rule_item_process_path.go), but Windows paths are case-insensitive,
// so a rule written as d:\tmp\App.exe never matches an image the searcher
// reports as D:\tmp\app.exe. That failure is silent in the worst direction: in
// exclude mode a bypass rule that never matches leaves the traffic in the
// tunnel, and nothing anywhere reports an error.
//
// The canonical spelling is added, never substituted, so a path that already
// matches keeps matching. Only the case of each component is corrected;
// symlinks and junctions are deliberately left alone, because the searcher
// reports the path the image was loaded from rather than its final target.
func expandProcessPaths(paths []string) []string {
	expanded := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))

	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		expanded = append(expanded, path)
	}

	for _, path := range paths {
		add(path)
		if runtime.GOOS != "windows" {
			continue
		}
		canonical, err := canonicalWindowsPath(path)
		if err != nil {
			// Worth saying out loud: the usual cause is a typo or an app that
			// is not installed, and the rule will match nothing at runtime.
			fmt.Printf("process rule: cannot resolve %q on disk (%v); the rule will only match this exact spelling\n", path, err)
			continue
		}
		if canonical != path {
			fmt.Printf("process rule: %q is spelled %q on disk; matching both\n", path, canonical)
			add(canonical)
		}
	}

	return expanded
}

// canonicalWindowsPath rewrites each component of an absolute Windows path to
// the case the filesystem reports, by looking the component up in its parent
// directory. os.Stat cannot do this: it succeeds whatever case is given.
func canonicalWindowsPath(path string) (string, error) {
	volume := filepath.VolumeName(path)
	if volume == "" {
		return "", fmt.Errorf("not an absolute path with a drive letter")
	}

	rest := strings.Trim(path[len(volume):], `\/`)
	if rest == "" {
		return "", fmt.Errorf("no path below the drive letter")
	}

	current := strings.ToUpper(volume) + `\`
	for _, component := range strings.Split(rest, `\`) {
		entries, err := os.ReadDir(current)
		if err != nil {
			return "", err
		}
		match := ""
		for _, entry := range entries {
			if strings.EqualFold(entry.Name(), component) {
				match = entry.Name()
				break
			}
		}
		if match == "" {
			return "", fmt.Errorf("%s not found in %s", component, current)
		}
		current = filepath.Join(current, match)
	}

	return current, nil
}
