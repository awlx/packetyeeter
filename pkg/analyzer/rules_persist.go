package analyzer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/scrubrules"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	ruleStateFile = "scrub-rules.json"
	// JSON is larger than the encoded protos the store is capped at; this
	// bounds what a damaged or planted file can make the analyzer read.
	maxRuleStateBytes = 8 * maxRuleSetBytes
)

type persistedRules struct {
	Version int                                   `json:"version"`
	Saved   time.Time                             `json:"saved"`
	Scopes  map[string]map[string]json.RawMessage `json:"scopes"` // scope -> wire id -> protojson Rule
}

// ruleStatePersister writes the desired rules so an analyzer restart does
// not leave scrub collectors without rules until the controller pushes again.
type ruleStatePersister struct {
	path string
	mu   sync.Mutex // serialises writers so the newest snapshot lands last
}

func (s *ruleStore) snapshot() map[string]map[string]*apiv1.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]map[string]*apiv1.Rule, len(s.scopes))
	for scope, set := range s.scopes {
		c := make(map[string]*apiv1.Rule, len(set))
		for id, r := range set {
			c[id] = proto.Clone(r).(*apiv1.Rule)
		}
		out[scope] = c
	}
	return out
}

// save writes the store's current rules atomically: a crash mid-write leaves
// the previous file intact rather than a truncated one.
func (p *ruleStatePersister) save(store *ruleStore) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	doc := persistedRules{Version: 1, Saved: time.Now().UTC(), Scopes: map[string]map[string]json.RawMessage{}}
	for scope, set := range store.snapshot() {
		enc := make(map[string]json.RawMessage, len(set))
		for id, r := range set {
			b, err := protojson.Marshal(r)
			if err != nil {
				return fmt.Errorf("encode rule %s: %w", id, err)
			}
			enc[id] = b
		}
		doc.Scopes[scope] = enc
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode rule state: %w", err)
	}

	dir := filepath.Dir(p.path)
	tmp, err := os.CreateTemp(dir, ruleStateFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("create rule state temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("restrict rule state file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write rule state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync rule state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close rule state: %w", err)
	}
	if err := os.Rename(tmp.Name(), p.path); err != nil {
		return fmt.Errorf("replace rule state: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: makes the rename itself durable
		d.Close()
	}
	return nil
}

// load restores rules into store. Expired or invalid rules are skipped and
// logged; a scope that no longer fits the limits is skipped as a whole.
// A file that cannot be read as rule state is moved aside so the next save
// does not overwrite the evidence.
func (p *ruleStatePersister) load(store *ruleStore, now time.Time) (restored int, err error) {
	f, err := os.Open(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open rule state: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRuleStateBytes+1))
	f.Close()
	if err != nil {
		return 0, fmt.Errorf("read rule state: %w", err)
	}

	var doc persistedRules
	switch {
	case len(data) > maxRuleStateBytes:
		err = fmt.Errorf("rule state is larger than %d bytes", maxRuleStateBytes)
	default:
		if uerr := json.Unmarshal(data, &doc); uerr != nil {
			err = fmt.Errorf("decode rule state: %w", uerr)
		} else if doc.Version != 1 {
			err = fmt.Errorf("unsupported rule state version %d", doc.Version)
		}
	}
	if err != nil {
		aside := fmt.Sprintf("%s.corrupt-%d", p.path, now.Unix())
		if rerr := os.Rename(p.path, aside); rerr != nil {
			return 0, fmt.Errorf("%w (moving it aside failed: %v)", err, rerr)
		}
		return 0, fmt.Errorf("%w; moved to %s", err, aside)
	}

	scopes := make([]string, 0, len(doc.Scopes))
	for scope := range doc.Scopes {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		log := logrus.WithField("scope", scope)
		if scope == "" || strings.Contains(scope, ruleScopeSep) {
			log.Error("Skipping persisted rules with an invalid scope")
			continue
		}
		set := map[string]*apiv1.Rule{}
		for id, raw := range doc.Scopes[scope] {
			var r apiv1.Rule
			if err := protojson.Unmarshal(raw, &r); err != nil {
				log.WithError(err).WithField("rule", id).Error("Skipping unreadable persisted rule")
				continue
			}
			if r.GetId() != id || !strings.HasPrefix(id, scope+ruleScopeSep) {
				log.WithField("rule", id).Error("Skipping persisted rule whose id does not match its scope")
				continue
			}
			if !now.Before(r.GetExpiresAt().AsTime()) {
				continue
			}
			if _, err := scrubrules.Parse(&r, now); err != nil {
				log.WithError(err).WithField("rule", id).Error("Skipping invalid persisted rule")
				continue
			}
			set[id] = &r
		}
		if len(set) == 0 {
			continue
		}
		if err := store.replace(scope, set, now); err != nil {
			log.WithError(err).Error("Skipping persisted scope that no longer fits")
			continue
		}
		restored += len(set)
	}
	return restored, nil
}

// persistRules saves the rule store if persistence is on. The rules are
// already live when this runs, so a failed save is reported, not returned.
func (a *Analyzer) persistRules() {
	if a.rulePersister == nil {
		return
	}
	if err := a.rulePersister.save(&a.rules); err != nil {
		metrics.RuleStateErrors.WithLabelValues("save").Inc()
		logrus.WithError(err).Error("Failed to persist scrub rules; they will not survive an analyzer restart")
	}
}

// restoreRules loads persisted rules before collectors connect, so the first
// set each scrub collector receives already contains them.
func (a *Analyzer) restoreRules() {
	if a.Config.RuleStateDir == "" {
		return
	}
	if !a.Config.EnableRuleAPI {
		logrus.Warn("-rule-state-dir has no effect without -enable-rule-api; persisted rules are not loaded")
		return
	}
	a.rulePersister = &ruleStatePersister{path: filepath.Join(a.Config.RuleStateDir, ruleStateFile)}
	n, err := a.rulePersister.load(&a.rules, time.Now())
	if err != nil {
		metrics.RuleStateErrors.WithLabelValues("load").Inc()
		logrus.WithError(err).Error("Failed to restore persisted scrub rules; starting without them")
		return
	}
	logrus.WithFields(logrus.Fields{"rules": n, "path": a.rulePersister.path}).Info("Restored persisted scrub rules")
}
