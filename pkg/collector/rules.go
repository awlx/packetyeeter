package collector

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/scrubrules"

	"github.com/sirupsen/logrus"
)

// ruleMaps is the kernel side of the rule engine, faked in tests.
type ruleMaps interface {
	PutRuleBody(slot uint16, rule *ebpf.ScrubRule) error
	ResetRuleBucket(slot uint16) error
	SwapRuleTrie(v6 bool, entries map[netip.Prefix][]uint16) error
}

// slotGrace is how long a replaced rule body stays reserved. XDP readers of
// the previous trie finish within microseconds; this only has to outlast them.
const slotGrace = time.Second

type installedRule struct {
	slot uint16
	body ebpf.ScrubRule
}

type retiredSlot struct {
	slot uint16
	at   time.Time
}

// ruleEngine owns the scrub-mode runtime rules: it applies deltas
// all-or-nothing, expires rules, and keeps the kernel tries in sync.
type ruleEngine struct {
	mu        sync.Mutex
	maps      ruleMaps
	rules     map[string]*scrubrules.Rule
	installed map[string]installedRule
	free      []uint16
	retired   []retiredSlot

	// Read by metrics scrapes, which must not wait for a rebuild.
	activeV4, activeV6 atomic.Int64
}

func newRuleEngine(m ruleMaps) *ruleEngine {
	e := &ruleEngine{
		maps:      m,
		rules:     map[string]*scrubrules.Rule{},
		installed: map[string]installedRule{},
		free:      make([]uint16, 0, ebpf.RuleSlots),
	}
	for s := ebpf.RuleSlots - 1; s >= 0; s-- {
		e.free = append(e.free, uint16(s))
	}
	return e
}

type ruleApplyResult struct {
	Upserted, Removed  int
	ActiveV4, ActiveV6 int
}

// Apply validates the whole delta before changing anything; one bad rule
// rejects all of it.
func (e *ruleEngine) Apply(delta *apiv1.RuleSetDelta, now time.Time) (ruleApplyResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	next := maps.Clone(e.rules)
	removed := 0
	if delta.GetReplace() {
		next = map[string]*scrubrules.Rule{}
	}
	for _, id := range delta.GetRemove() {
		if _, ok := next[id]; ok {
			delete(next, id)
			removed++
		}
	}
	seen := map[string]bool{}
	for _, pr := range delta.GetUpsert() {
		r, err := scrubrules.Parse(pr, now)
		if err != nil {
			return ruleApplyResult{}, err
		}
		if seen[r.ID] {
			return ruleApplyResult{}, fmt.Errorf("rule %q appears twice in one delta", r.ID)
		}
		seen[r.ID] = true
		next[r.ID] = r
	}
	if delta.GetReplace() {
		for id := range e.rules {
			if _, ok := next[id]; !ok {
				removed++
			}
		}
	}
	if err := e.install(next, now); err != nil {
		return ruleApplyResult{}, err
	}
	res := ruleApplyResult{Upserted: len(seen), Removed: removed}
	res.ActiveV4, res.ActiveV6 = e.Counts()
	return res, nil
}

// Expire removes rules whose expiry has passed and returns their ids.
func (e *ruleEngine) Expire(now time.Time) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var expired []string
	for id, r := range e.rules {
		if !now.Before(r.Expires) {
			expired = append(expired, id)
		}
	}
	if len(expired) == 0 {
		e.releaseRetired(now)
		return nil, nil
	}
	next := maps.Clone(e.rules)
	for _, id := range expired {
		delete(next, id)
	}
	if err := e.install(next, now); err != nil {
		return nil, err
	}
	slices.Sort(expired)
	return expired, nil
}

func (e *ruleEngine) Counts() (v4, v6 int) {
	return int(e.activeV4.Load()), int(e.activeV6.Load())
}

// install makes next the active rule set. On error the kernel keeps the
// previous tries and e.rules is unchanged.
func (e *ruleEngine) install(next map[string]*scrubrules.Rule, now time.Time) error {
	e.releaseRetired(now)

	v4, v6 := scrubrules.SplitFamilies(next)
	if len(v4) > ebpf.RulesMax || len(v6) > ebpf.RulesMax {
		return fmt.Errorf("too many rules: %d IPv4, %d IPv6 (at most %d per family)", len(v4), len(v6), ebpf.RulesMax)
	}
	entries4, err := scrubrules.Flatten(v4)
	if err != nil {
		return err
	}
	entries6, err := scrubrules.Flatten(v6)
	if err != nil {
		return err
	}

	// Unchanged rules keep their slot, and with it their rate-limit window.
	slots := make(map[string]uint16, len(next))
	var fresh []uint16
	rollback := func() { e.free = append(e.free, fresh...) }
	for id, r := range next {
		if cur, ok := e.installed[id]; ok && cur.body == r.Body {
			slots[id] = cur.slot
			continue
		}
		if len(e.free) == 0 {
			rollback()
			return errors.New("no free rule slots; retry once replaced rules are released")
		}
		slot := e.free[len(e.free)-1]
		e.free = e.free[:len(e.free)-1]
		fresh = append(fresh, slot)
		if err := e.maps.PutRuleBody(slot, &r.Body); err != nil {
			rollback()
			return fmt.Errorf("write rule %q: %w", id, err)
		}
		if err := e.maps.ResetRuleBucket(slot); err != nil {
			rollback()
			return fmt.Errorf("reset rate limit of rule %q: %w", id, err)
		}
		slots[id] = slot
	}

	// Each family's trie is swapped in one map update; a packet is only ever
	// matched against one family.
	if err := e.maps.SwapRuleTrie(false, slotEntries(entries4, slots)); err != nil {
		rollback()
		return err
	}
	if err := e.maps.SwapRuleTrie(true, slotEntries(entries6, slots)); err != nil {
		// Put the previous IPv4 rules back. If that fails too, the next
		// successful install rebuilds both tries from scratch.
		old4, _ := scrubrules.SplitFamilies(e.rules)
		prev, ferr := scrubrules.Flatten(old4)
		if ferr == nil {
			ferr = e.maps.SwapRuleTrie(false, slotEntries(prev, e.installedSlots()))
		}
		if ferr != nil {
			// The live IPv4 trie may still point at the fresh slots, so they
			// must not be handed out again before the grace period.
			for _, slot := range fresh {
				e.retired = append(e.retired, retiredSlot{slot: slot, at: now})
			}
			return fmt.Errorf("%w (restoring the previous IPv4 rules also failed: %v)", err, ferr)
		}
		rollback()
		return err
	}
	e.commit(next, slots, now)
	return nil
}

func (e *ruleEngine) installedSlots() map[string]uint16 {
	out := make(map[string]uint16, len(e.installed))
	for id, ir := range e.installed {
		out[id] = ir.slot
	}
	return out
}

func (e *ruleEngine) commit(next map[string]*scrubrules.Rule, slots map[string]uint16, now time.Time) {
	installed := make(map[string]installedRule, len(next))
	for id, r := range next {
		installed[id] = installedRule{slot: slots[id], body: r.Body}
	}
	for id, cur := range e.installed {
		if n, ok := installed[id]; !ok || n.slot != cur.slot {
			e.retired = append(e.retired, retiredSlot{slot: cur.slot, at: now})
		}
	}
	e.installed = installed
	e.rules = next
	v4, v6 := scrubrules.SplitFamilies(next)
	e.activeV4.Store(int64(len(v4)))
	e.activeV6.Store(int64(len(v6)))
}

func (e *ruleEngine) releaseRetired(now time.Time) {
	kept := e.retired[:0]
	for _, r := range e.retired {
		if now.Sub(r.at) >= slotGrace {
			e.free = append(e.free, r.slot)
		} else {
			kept = append(kept, r)
		}
	}
	e.retired = kept
}

func slotEntries(entries map[netip.Prefix][]*scrubrules.Rule, slots map[string]uint16) map[netip.Prefix][]uint16 {
	out := make(map[netip.Prefix][]uint16, len(entries))
	for p, rules := range entries {
		s := make([]uint16, len(rules))
		for i, r := range rules {
			s[i] = slots[r.ID]
		}
		out[p] = s
	}
	return out
}

func (c *Collector) applyRules(delta *apiv1.RuleSetDelta) {
	if c.rules == nil {
		c.Logger.Warn("Ignoring COMMAND_SET_RULES: runtime rules need -mode scrub")
		return
	}
	res, err := c.rules.Apply(delta, time.Now())
	if err != nil {
		c.Logger.WithError(err).WithFields(logrus.Fields{
			"upsert": len(delta.GetUpsert()),
			"remove": len(delta.GetRemove()),
		}).Warn("Rejected rule delta; previous rules stay active")
		return
	}
	if c.analyzerReady != nil {
		c.analyzerReady.markSynced()
	}
	c.Logger.WithFields(logrus.Fields{
		"upserted":  res.Upserted,
		"removed":   res.Removed,
		"active_v4": res.ActiveV4,
		"active_v6": res.ActiveV6,
	}).Info("Applied rule delta")
}

func (c *Collector) runRuleExpiry() {
	defer c.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			expired, err := c.rules.Expire(now)
			if err != nil {
				c.Logger.WithError(err).Warn("Failed to remove expired rules")
			}
			if len(expired) > 0 {
				c.Logger.WithField("rules", expired).Info("Removed expired rules")
			}
		}
	}
}
