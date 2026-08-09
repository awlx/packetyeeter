package sustained

import (
	"fmt"
	"testing"
	"time"
)

// clock is a manually advanced time source so window and hold behavior can be
// tested without sleeping.
type clock struct{ t time.Time }

func newClock() *clock {
	return &clock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

// testConfig is small enough to drive from a test but keeps the same shape as
// production: breadth floors well above one, and a byte floor far above what
// the shape path needs.
func testConfig() Config {
	return Config{
		Enabled:                           true,
		Enforce:                           true,
		WindowSeconds:                     60,
		EvaluationIntervalSeconds:         1,
		PublishIntervalSeconds:            1,
		MinimumRequests:                   10,
		MinimumBytes:                      1 << 20,
		MinimumResources:                  10,
		MinimumSections:                   5,
		MaximumResourcesPerSectionPercent: 120,
		MaximumClients:                    100,
		MaximumResourcesPerClient:         50,
		HoldSeconds:                       120,
		MaximumHoldSeconds:                240,
		ReleaseFactorPercent:              100,
		ReputationFactor:                  4,
	}
}

// walk issues count requests to distinct resources, one per section, which is
// the shape of enumeration.
func walk(t *Tracker, ip string, count int) {
	for i := 0; i < count; i++ {
		t.ObserveRequest(ip, "example.test", fmt.Sprintf("/s%d/r%d", i, i))
	}
}

// mirror issues count requests to distinct resources concentrated in sections
// sections, which is the shape of a bulk download.
func mirror(t *Tracker, ip string, count, sections int) {
	for i := 0; i < count; i++ {
		t.ObserveRequest(ip, "example.test", fmt.Sprintf("/s%d/r%d", i%sections, i))
	}
}

func TestDisabledTrackerIgnoresEverything(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	tracker := New(cfg)

	walk(tracker, "10.0.0.1", 50)
	tracker.ObserveBytes("10.0.0.1", 1<<30)

	if got := tracker.Stats().TrackedClients; got != 0 {
		t.Fatalf("tracked clients = %d, want 0", got)
	}
	if decisions := tracker.Evaluate(); decisions != nil {
		t.Fatalf("decisions = %v, want none", decisions)
	}
}

func TestShapePathSelectsEnumerationWithoutBytes(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	// One resource per section, no bytes at all: the shape path has no byte
	// floor precisely so this is caught.
	walk(tracker, "10.0.0.1", 20)

	c.advance(2 * time.Second)
	decisions := tracker.Evaluate()
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}
	if decisions[0].Path != "shape" {
		t.Fatalf("path = %q, want shape", decisions[0].Path)
	}
	if decisions[0].Bytes != 0 {
		t.Fatalf("bytes = %d, want 0", decisions[0].Bytes)
	}
}

func TestDeepClientIsNotSelectedByShape(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	// Plenty of resources and enough sections, but concentrated: the ratio is
	// 4.0, well over the 1.2 ceiling.
	mirror(tracker, "10.0.0.1", 40, 10)

	c.advance(2 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 0 {
		t.Fatalf("decisions = %v, want none for a deep client under the byte floor", decisions)
	}
}

func TestVolumePathSelectsDeepClientWithBytes(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	mirror(tracker, "10.0.0.1", 40, 10)
	tracker.ObserveBytes("10.0.0.1", 4<<20)

	c.advance(2 * time.Second)
	decisions := tracker.Evaluate()
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}
	if decisions[0].Path != "volume" {
		t.Fatalf("path = %q, want volume", decisions[0].Path)
	}
}

func TestObserveBytesDoesNotCreateClients(t *testing.T) {
	tracker := New(testConfig())

	tracker.ObserveBytes("10.0.0.9", 8<<30)

	if got := tracker.Stats().TrackedClients; got != 0 {
		t.Fatalf("tracked clients = %d, want 0; bytes alone can never select a client", got)
	}
}

func TestBoundedSetEvictsOldestRatherThanRejecting(t *testing.T) {
	c := newClock()
	set := newBoundedSet(3)

	for _, key := range []uint64{1, 2, 3} {
		if added, _, _ := set.Observe(key, key, c.now()); !added {
			t.Fatalf("key %d not added", key)
		}
	}

	c.advance(time.Second)
	added, evicted, didEvict := set.Observe(4, 4, c.now())
	if !added {
		t.Fatal("new key rejected; a full set must evict the oldest entry, not refuse new ones")
	}
	if !didEvict || evicted != 1 {
		t.Fatalf("evicted = %d (%v), want the oldest entry, section 1", evicted, didEvict)
	}
	if set.Len() != 3 {
		t.Fatalf("len = %d, want 3", set.Len())
	}
}

// A forward walker never revisits a resource. If a full set rejected new
// entries instead of evicting, every retained entry would age out together one
// window later and the client's resource count would collapse to zero. This
// asserts it stays at the cap instead.
func TestForwardWalkerKeepsResourceCountAtCapAcrossWindow(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.MaximumResourcesPerClient = 20
	tracker := New(cfg, WithClock(c.now))

	for i := 0; i < 200; i++ {
		tracker.ObserveRequest("10.0.0.1", "example.test", fmt.Sprintf("/s%d/r%d", i, i))
		c.advance(time.Second)
	}

	tracker.mu.Lock()
	resources := tracker.clients["10.0.0.1"].Resources.Len()
	tracker.mu.Unlock()

	if resources != 20 {
		t.Fatalf("resources = %d, want the cap of 20 after walking well past a window", resources)
	}
}

// Section cardinality has to be reference counted off the retained resource
// set. If evicting a resource left its section behind, a concentrated client
// would drift toward one section per resource and start looking like
// enumeration.
func TestSectionsAreReferenceCountedOffRetainedResources(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.MaximumResourcesPerClient = 10
	tracker := New(cfg, WithClock(c.now))

	// 100 resources spread over only 5 sections.
	mirror(tracker, "10.0.0.1", 100, 5)

	tracker.mu.Lock()
	client := tracker.clients["10.0.0.1"]
	resources, sections := client.Resources.Len(), client.sectionCount()
	tracker.mu.Unlock()

	if resources != 10 {
		t.Fatalf("resources = %d, want 10", resources)
	}
	if sections > 5 {
		t.Fatalf("sections = %d, want at most 5; sections leaked past resource eviction", sections)
	}
}

func TestWindowExpiryDropsCounts(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	walk(tracker, "10.0.0.1", 20)
	tracker.ObserveBytes("10.0.0.1", 4<<20)

	c.advance(90 * time.Second)
	tracker.ObserveRequest("10.0.0.1", "example.test", "/other/x")

	tracker.mu.Lock()
	client := tracker.clients["10.0.0.1"]
	requests, bytes := client.totals()
	resources := client.Resources.Len()
	tracker.mu.Unlock()

	if requests != 1 {
		t.Fatalf("requests = %d, want 1 after the window rolled over", requests)
	}
	if bytes != 0 {
		t.Fatalf("bytes = %d, want 0 after the window rolled over", bytes)
	}
	if resources != 1 {
		t.Fatalf("resources = %d, want 1 after the window rolled over", resources)
	}
}

func TestReputationRaisesThresholdsRatherThanExempting(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	tracker := New(cfg, WithClock(c.now),
		WithReputation(func(string) bool { return true }))

	// Over the base request floor but under the raised one.
	walk(tracker, "10.0.0.1", 20)
	c.advance(2 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 0 {
		t.Fatalf("decisions = %v, want none while under the raised threshold", decisions)
	}
	if got := tracker.Stats().ReputationDeferrals; got == 0 {
		t.Fatal("reputation deferrals = 0, want the deferral to be counted")
	}

	// Push past the raised floor: reputation raises the bar, it does not
	// remove it.
	for i := 20; i < 60; i++ {
		tracker.ObserveRequest("10.0.0.1", "example.test", fmt.Sprintf("/s%d/r%d", i, i))
	}
	c.advance(2 * time.Second)
	decisions := tracker.Evaluate()
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1 once the raised threshold is cleared", len(decisions))
	}
	if !decisions[0].GoodReputation || decisions[0].ThresholdFactor != cfg.ReputationFactor {
		t.Fatalf("decision = %+v, want good reputation with the raised factor", decisions[0])
	}
}

func TestHoldKeepsSelectedClientAndCeilingReleasesIt(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.PublishIntervalSeconds = 1
	tracker := New(cfg, WithClock(c.now))

	walk(tracker, "10.0.0.1", 20)
	c.advance(2 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 1 || decisions[0].Held {
		t.Fatalf("decisions = %v, want one fresh selection", decisions)
	}

	// The window ages out, as it would once the client is blocked and stops
	// being served. The hold is what keeps the block in place.
	c.advance(90 * time.Second)
	tracker.ObserveRequest("10.0.0.1", "example.test", "/keepalive/x")
	decisions := tracker.Evaluate()
	if len(decisions) != 1 || !decisions[0].Held {
		t.Fatalf("decisions = %v, want the client held after its evidence aged out", decisions)
	}

	// Past the ceiling the hold must end regardless, because nothing
	// measurable separates a false positive from a suppressed true positive.
	for i := 0; i < 6; i++ {
		c.advance(60 * time.Second)
		tracker.ObserveRequest("10.0.0.1", "example.test", "/keepalive/x")
		decisions = tracker.Evaluate()
	}
	if len(decisions) != 0 {
		t.Fatalf("decisions = %v, want release once the hold ceiling passed", decisions)
	}
}

func TestHoldDisabledByNegativeConfig(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.HoldSeconds = -1
	tracker := New(cfg, WithClock(c.now))

	walk(tracker, "10.0.0.1", 20)
	c.advance(2 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}

	c.advance(90 * time.Second)
	tracker.ObserveRequest("10.0.0.1", "example.test", "/keepalive/x")
	if decisions := tracker.Evaluate(); len(decisions) != 0 {
		t.Fatalf("decisions = %v, want none with the hold disabled", decisions)
	}
}

func TestPublishIntervalSuppressesRepeatDecisions(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.PublishIntervalSeconds = 60
	tracker := New(cfg, WithClock(c.now))

	walk(tracker, "10.0.0.1", 20)
	c.advance(2 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}

	c.advance(5 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 0 {
		t.Fatalf("decisions = %v, want none inside the publish interval", decisions)
	}
}

func TestEvaluationIntervalRateLimitsEvaluation(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.EvaluationIntervalSeconds = 30
	tracker := New(cfg, WithClock(c.now))

	walk(tracker, "10.0.0.1", 20)
	if decisions := tracker.Evaluate(); len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1 on the first evaluation", len(decisions))
	}
	c.advance(5 * time.Second)
	if decisions := tracker.Evaluate(); decisions != nil {
		t.Fatalf("decisions = %v, want none inside the evaluation interval", decisions)
	}
}

func TestClientEvictionIsBoundedAndCounted(t *testing.T) {
	cfg := testConfig()
	cfg.MaximumClients = 5
	tracker := New(cfg)

	for i := 0; i < 20; i++ {
		tracker.ObserveRequest(fmt.Sprintf("10.0.0.%d", i), "example.test", "/a/b")
	}

	stats := tracker.Stats()
	if stats.TrackedClients != 5 {
		t.Fatalf("tracked clients = %d, want the cap of 5", stats.TrackedClients)
	}
	if stats.ClientEvictions != 15 {
		t.Fatalf("client evictions = %d, want 15", stats.ClientEvictions)
	}
}

// The tracker reports only its own configured intent. Whether a decision
// actually becomes a block depends on analyzer-wide state (dry-run, the runtime
// kill switch) that this package deliberately knows nothing about, which is why
// Snapshot takes the enforcing flag from its caller.
func TestSnapshotActionFollowsCallerEnforcementState(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	if !tracker.Enforcing() {
		t.Fatal("Enforcing = false, want true for an enabled+enforce config")
	}

	walk(tracker, "10.0.0.1", 20)
	c.advance(2 * time.Second)
	if decisions := tracker.Evaluate(); len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}

	if snapshots := tracker.Snapshot(10, "requests", false); len(snapshots) != 1 || snapshots[0].Action != ActionWouldBlock {
		t.Fatalf("snapshot = %+v, want would_block when the caller is not enforcing", snapshots)
	}
	if snapshots := tracker.Snapshot(10, "requests", true); len(snapshots) != 1 || snapshots[0].Action != ActionBlocking {
		t.Fatalf("snapshot = %+v, want blocking when the caller is enforcing", snapshots)
	}
}

func TestEnforcingFollowsConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Enforce = false
	if New(cfg).Enforcing() {
		t.Fatal("Enforcing = true with Enforce disabled")
	}

	cfg = testConfig()
	cfg.Enabled = false
	if New(cfg).Enforcing() {
		t.Fatal("Enforcing = true with the tracker disabled")
	}
}

func TestIdleClientIsDropped(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	tracker.ObserveRequest("10.0.0.1", "example.test", "/a/b")
	c.advance(5 * time.Minute)
	tracker.Evaluate()

	if got := tracker.Stats().TrackedClients; got != 0 {
		t.Fatalf("tracked clients = %d, want 0 after two windows of silence", got)
	}
}

func TestSnapshotReportsBlockersAndAction(t *testing.T) {
	c := newClock()
	tracker := New(testConfig(), WithClock(c.now))

	walk(tracker, "10.0.0.1", 5)

	snapshots := tracker.Snapshot(10, "requests", false)
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snapshots))
	}
	got := snapshots[0]
	if got.Action != ActionWatching {
		t.Fatalf("action = %q, want watching", got.Action)
	}
	if len(got.Blockers) == 0 {
		t.Fatal("blockers empty, want the thresholds the client is under")
	}
	if got.Margins["requests"] != 50 {
		t.Fatalf("requests margin = %d, want 50", got.Margins["requests"])
	}
}

func TestResourceKeysIgnoreQueryAndGroupBySection(t *testing.T) {
	plain, section := resourceKeys("Example.test", "/repo/file")
	withQuery, sectionAgain := resourceKeys("example.test", "/repo/file?ref=main")
	if plain != withQuery {
		t.Fatal("query string changed the resource key; it must be stripped")
	}
	if section != sectionAgain {
		t.Fatal("query string changed the section key")
	}

	_, sibling := resourceKeys("example.test", "/repo/other")
	if section != sibling {
		t.Fatal("sibling resources landed in different sections")
	}

	_, elsewhere := resourceKeys("example.test", "/different/file")
	if section == elsewhere {
		t.Fatal("different first segments shared a section")
	}
}

func TestHashSeparatorKeepsConcatenationsDistinct(t *testing.T) {
	if hash64("ab", "c") == hash64("a", "bc") {
		t.Fatal("hash64 collided on a shifted split; the separator is missing")
	}
}
