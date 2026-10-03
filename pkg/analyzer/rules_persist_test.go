package analyzer

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func persistingAnalyzer(t *testing.T, dir string) *Analyzer {
	t.Helper()
	a := newRuleAnalyzer(t)
	a.Config.RuleStateDir = dir
	a.restoreRules()
	return a
}

func desiredIDs(a *Analyzer) []string {
	return slices.Collect(maps.Keys(a.rules.desired(time.Now(), true)))
}

func writeRuleState(t *testing.T, dir string, scopes map[string][]*apiv1.Rule) {
	t.Helper()
	doc := persistedRules{Version: 1, Scopes: map[string]map[string]json.RawMessage{}}
	for scope, rules := range scopes {
		doc.Scopes[scope] = map[string]json.RawMessage{}
		for _, r := range rules {
			b, err := protojson.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			doc.Scopes[scope][r.GetId()] = b
		}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ruleStateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func wireRule(scope, id string) *apiv1.Rule {
	r := dropRule(id)
	r.Id = scope + ruleScopeSep + id
	return r
}

func TestPersistedRulesSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	a := persistingAnalyzer(t, dir)
	push(t, a, "a", dropRule("x"), dropRule("y"))
	push(t, a, "b", dropRule("x"))

	info, err := os.Stat(filepath.Join(dir, ruleStateFile))
	if err != nil {
		t.Fatalf("rule state not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("rule state mode = %o, want 600", perm)
	}

	b := persistingAnalyzer(t, dir)
	assertIDs(t, "restored", desiredIDs(b), []string{"a/x", "a/y", "b/x"})

	// The restored set is what a scrub collector gets first.
	_, first := addCollector(t, b, "scrub")
	assertIDs(t, "first set", upsertIDs(first), []string{"a/x", "a/y", "b/x"})
}

func TestClearedScopeIsRemovedFromRuleState(t *testing.T) {
	dir := t.TempDir()
	a := persistingAnalyzer(t, dir)
	push(t, a, "a", dropRule("x"))
	push(t, a, "b", dropRule("x"))
	push(t, a, "a")

	b := persistingAnalyzer(t, dir)
	assertIDs(t, "restored", desiredIDs(b), []string{"b/x"})
}

func TestRuleStateSkipsExpiredAndForeignRules(t *testing.T) {
	dir := t.TempDir()
	expired := wireRule("a", "old")
	expired.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
	foreign := wireRule("b", "sneaky") // stored under scope a
	writeRuleState(t, dir, map[string][]*apiv1.Rule{
		"a":       {wireRule("a", "keep"), expired, foreign},
		"bad/one": {wireRule("bad/one", "z")},
	})

	a := persistingAnalyzer(t, dir)
	assertIDs(t, "restored", desiredIDs(a), []string{"a/keep"})
}

func TestCorruptRuleStateIsMovedAside(t *testing.T) {
	for name, data := range map[string][]byte{
		"not json":    []byte("{nope"),
		"bad version": []byte(`{"version":9,"scopes":{}}`),
		"oversized":   []byte(strings.Repeat(" ", maxRuleStateBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ruleStateFile)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			a := persistingAnalyzer(t, dir)
			if ids := desiredIDs(a); len(ids) != 0 {
				t.Fatalf("restored %v from a corrupt file", ids)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("corrupt rule state still in place: %v", err)
			}
			aside, _ := filepath.Glob(path + ".corrupt-*")
			if len(aside) != 1 {
				t.Fatalf("corrupt file not kept for inspection: %v", aside)
			}

			// The next push writes a fresh, loadable state.
			push(t, a, "a", dropRule("x"))
			assertIDs(t, "after recovery", desiredIDs(persistingAnalyzer(t, dir)), []string{"a/x"})
		})
	}
}

func TestRuleStateIgnoredWithoutRuleAPI(t *testing.T) {
	dir := t.TempDir()
	writeRuleState(t, dir, map[string][]*apiv1.Rule{"a": {wireRule("a", "x")}})

	a := newTestAnalyzer(t)
	a.Config.RuleStateDir = dir
	a.restoreRules()
	if ids := desiredIDs(a); len(ids) != 0 {
		t.Fatalf("rules restored with the rule API off: %v", ids)
	}
	if a.rulePersister != nil {
		t.Fatal("persister enabled with the rule API off")
	}
}

func TestNoRuleStateWithoutDir(t *testing.T) {
	a := newRuleAnalyzer(t)
	push(t, a, "a", dropRule("x"))
	if a.rulePersister != nil {
		t.Fatal("persister enabled without -rule-state-dir")
	}
}
