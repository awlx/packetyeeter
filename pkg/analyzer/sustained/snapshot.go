package sustained

import (
	"sort"
	"time"
)

// Action is what the tracker is currently doing about a client.
type Action string

const (
	// ActionWatching means the client is tracked but under every threshold.
	ActionWatching Action = "watching"
	// ActionWouldBlock means the client clears a threshold but enforcement is
	// off, either by config or because the kill switch has been pulled.
	ActionWouldBlock Action = "would_block"
	// ActionBlocking means the client clears a threshold and enforcement is on.
	ActionBlocking Action = "blocking"
)

// ClientSnapshot is one client as the reporting surfaces see it.
//
// It carries Blockers and Margins as well as the raw measurements because the
// question an operator actually has is "why is this client not being caught",
// and answering that from four counters and a config page is exactly the
// arithmetic the tracker already does.
type ClientSnapshot struct {
	IP        string `json:"ip"`
	Requests  uint64 `json:"requests"`
	Bytes     uint64 `json:"bytes"`
	Resources int    `json:"resources"`
	Sections  int    `json:"sections"`

	RequestsPerSecond float64 `json:"requests_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`
	// ResourcesPerSection is the shape path's discriminator, reported directly
	// so the ceiling can be tuned against observed traffic.
	ResourcesPerSection float64 `json:"resources_per_section"`

	GoodReputation  bool  `json:"good_reputation"`
	ThresholdFactor int64 `json:"threshold_factor"`

	Action Action `json:"action"`
	// Path names the selection path that matches, if any.
	Path string `json:"path,omitempty"`
	// Held reports that the client is kept selected by the hold rather than by
	// a current threshold crossing.
	Held bool `json:"held"`
	// HeldSeconds is how long it has been selected.
	HeldSeconds int `json:"held_seconds,omitempty"`

	// Blockers lists the thresholds this client is under, in the order they are
	// evaluated. Empty means the client clears every threshold on some path.
	Blockers []string `json:"blockers,omitempty"`
	// Margins is the fraction of each threshold the client has reached, as a
	// percentage. Values near 100 are the ones worth tuning.
	Margins map[string]int `json:"margins,omitempty"`
}

// Snapshot returns the top clients by the given ordering, most significant
// first. It does not advance the window or produce decisions.
//
// enforcing is supplied by the caller rather than read from the tracker,
// because whether a decision actually becomes a block depends on analyzer-wide
// state (dry-run, the runtime enforcement kill switch) that this package
// deliberately knows nothing about.
func (t *Tracker) Snapshot(limit int, by string, enforcing bool) []ClientSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	if limit <= 0 {
		limit = 25
	}

	now := t.now()
	window := float64(t.config.WindowSeconds)

	snapshots := make([]ClientSnapshot, 0, len(t.clients))
	for ip, client := range t.clients {
		requests, bytes := client.totals()
		resources := client.Resources.Len()
		sections := client.sectionCount()

		good := t.goodReputation != nil && t.goodReputation(ip)
		factor := int64(1)
		if good {
			factor = t.config.ReputationFactor
		}

		matched := matchThresholds(t.config, requests, bytes, resources, sections, uint64(factor))

		snapshot := ClientSnapshot{
			IP:              ip,
			Requests:        requests,
			Bytes:           bytes,
			Resources:       resources,
			Sections:        sections,
			GoodReputation:  good,
			ThresholdFactor: factor,
			Path:            matched.path(),
			Blockers:        blockers(t.config, requests, bytes, resources, sections, uint64(factor)),
			Margins:         margins(t.config, requests, bytes, resources, sections, uint64(factor)),
		}
		if window > 0 {
			snapshot.RequestsPerSecond = float64(requests) / window
			snapshot.BytesPerSecond = float64(bytes) / window
		}
		if sections > 0 {
			snapshot.ResourcesPerSection = float64(resources) / float64(sections)
		}
		if !client.SelectedSince.IsZero() {
			snapshot.HeldSeconds = int(now.Sub(client.SelectedSince) / time.Second)
			snapshot.Held = !matched.over()
		}

		switch {
		case !matched.over() && !snapshot.Held:
			snapshot.Action = ActionWatching
		case enforcing:
			snapshot.Action = ActionBlocking
		default:
			snapshot.Action = ActionWouldBlock
		}

		snapshots = append(snapshots, snapshot)
	}

	sortSnapshots(snapshots, by)
	if len(snapshots) > limit {
		snapshots = snapshots[:limit]
	}
	return snapshots
}

func sortSnapshots(snapshots []ClientSnapshot, by string) {
	less := func(i, j int) bool { return snapshots[i].Bytes > snapshots[j].Bytes }
	switch by {
	case "requests":
		less = func(i, j int) bool { return snapshots[i].Requests > snapshots[j].Requests }
	case "resources":
		less = func(i, j int) bool { return snapshots[i].Resources > snapshots[j].Resources }
	case "sections":
		less = func(i, j int) bool { return snapshots[i].Sections > snapshots[j].Sections }
	}
	sort.SliceStable(snapshots, less)
}

// blockers lists which thresholds a client is under. A client under nothing on
// at least one path returns nil.
func blockers(cfg Config, requests, bytes uint64, resources, sections int, factor uint64) []string {
	if matchThresholds(cfg, requests, bytes, resources, sections, factor).over() {
		return nil
	}

	var reasons []string
	if requests < cfg.MinimumRequests*factor {
		reasons = append(reasons, "requests")
	}
	if resources < cfg.MinimumResources {
		reasons = append(reasons, "resources")
	}
	if sections < cfg.MinimumSections {
		reasons = append(reasons, "sections")
	}
	// Bytes and the ratio are alternatives to each other rather than
	// requirements, so they are only reported once the shared floors are clear.
	// Listing them earlier would suggest a client needs both.
	if len(reasons) == 0 {
		if bytes < cfg.MinimumBytes*factor {
			reasons = append(reasons, "bytes")
		}
		if !resourcesPerSectionWithin(cfg.MaximumResourcesPerSectionPercent, resources, sections) {
			reasons = append(reasons, "resources_per_section")
		}
	}
	return reasons
}

// margins reports how close a client is to each threshold, as a percentage.
func margins(cfg Config, requests, bytes uint64, resources, sections int, factor uint64) map[string]int {
	result := map[string]int{
		"requests":  percentOf(requests, cfg.MinimumRequests*factor),
		"bytes":     percentOf(bytes, cfg.MinimumBytes*factor),
		"resources": percentOf(uint64(resources), uint64(cfg.MinimumResources)),
		"sections":  percentOf(uint64(sections), uint64(cfg.MinimumSections)),
	}
	if sections > 0 && cfg.MaximumResourcesPerSectionPercent > 0 {
		// Inverted: this threshold is a ceiling, so a client is closer to
		// matching as the ratio falls. 100 means it is exactly at the ceiling.
		ratio := float64(resources) / float64(sections) * 100
		ceiling := float64(cfg.MaximumResourcesPerSectionPercent)
		result["resources_per_section"] = int(ceiling / max(ratio, 1) * 100)
	}
	return result
}

func percentOf(value, threshold uint64) int {
	if threshold == 0 {
		return 100
	}
	percent := value * 100 / threshold
	if percent > 100 {
		return 100
	}
	return int(percent)
}
