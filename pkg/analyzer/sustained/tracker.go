// Package sustained detects clients that pull an unusual amount of data or walk
// an unusual breadth of resources over a sliding window.
//
// It exists because rate limiting alone cannot see this class of abuse. A
// scraper or mirror that stays under every per-second limit but sustains that
// rate for an hour, across thousands of distinct resources, is invisible to a
// request-rate threshold and obvious over a five-minute window.
//
// Two independent selection paths run over the same window:
//
//   - Volume: a client moving a large number of bytes across many resources.
//     Catches bulk mirroring and content theft.
//   - Shape: a client touching many resources spread thinly across many
//     sections, with no byte floor at all. Catches enumeration, which is
//     defined by breadth rather than volume and would otherwise need a byte
//     threshold low enough to sweep up legitimate traffic.
//
// Nothing in this package stores request paths or hostnames. Resource identity
// is reduced to a 64-bit hash on the way in, because the tracker only ever
// needs to count distinct values and compare them, never read them back.
package sustained

import (
	"container/list"
	"hash/fnv"
	"strings"
	"sync"
	"time"
)

// bucketSize is the granularity of the sliding window. Summing a handful of
// fixed buckets keeps both accumulation and pruning O(buckets) per client,
// which is what makes a five-minute window affordable across many clients.
const bucketSize = 10 * time.Second

// Decision is one client selected for action during an evaluation.
type Decision struct {
	IP              string
	Requests        uint64
	Bytes           uint64
	Resources       int
	Sections        int
	GoodReputation  bool
	ThresholdFactor int64
	// Path names which selection path chose this client: "volume", "shape" or
	// "volume+shape". Empty means the client is being held rather than
	// currently clearing a threshold.
	Path string
	// Held reports that the client no longer clears any threshold and is being
	// kept selected by the hold. Enforcement is what removed the evidence, so
	// this is the expected steady state for a client the block is working on.
	Held bool
}

// Stats is the tracker's own health, as distinct from what it has detected.
type Stats struct {
	TrackedClients int
	Decisions      uint64
	// ClientEvictions counts clients dropped because the tracker hit its
	// client ceiling. A nonzero and growing value means the window is being
	// shared by more clients than it was sized for, and detection is being
	// applied to an arbitrary subset of them.
	ClientEvictions uint64
	// ResourceEvictions counts distinct resources dropped because a client hit
	// its per-client resource cap. Expected and harmless for broad clients: it
	// means the client is at the cap, which is itself the signal.
	ResourceEvictions uint64
	// ReputationDeferrals counts evaluations where a client cleared the base
	// thresholds but was held below the reputation-raised ones.
	ReputationDeferrals uint64
	// LongDeferredClients counts good-reputation clients that have been sitting
	// between the base and raised thresholds for at least a full window. A
	// nonzero value is a tuning signal: something is persistently borderline.
	LongDeferredClients int
	// HeldClients counts clients kept selected by the hold rather than by a
	// current threshold crossing. A growing value means blocked clients are not
	// backing off.
	HeldClients int
}

// Config controls detection. Every zero value is replaced with a documented
// default by New, so a zero Config is usable and conservative.
type Config struct {
	// Enabled turns measurement on. When false the tracker ignores everything
	// it is given and produces no decisions.
	Enabled bool
	// Enforce turns decisions into blocks. When false the tracker still
	// measures and reports, and every decision is logged as "would block".
	// This is deliberately separate from Enabled so a deployment can run
	// detect-only for as long as it takes to tune.
	Enforce bool

	WindowSeconds             int
	EvaluationIntervalSeconds int
	// PublishIntervalSeconds is the minimum gap between decisions for the same
	// client, so a client that stays over threshold is not re-decided on every
	// evaluation tick.
	PublishIntervalSeconds int

	MinimumRequests  uint64
	MinimumBytes     uint64
	MinimumResources int
	MinimumSections  int

	// MaximumResourcesPerSectionPercent is the shape path's ceiling, as a
	// percentage. A client whose resources-per-section ratio is at or below it
	// is spreading itself thinly across sections, which is what separates
	// enumeration from a client legitimately pulling many resources out of a
	// few sections.
	MaximumResourcesPerSectionPercent int

	MaximumClients            int
	MaximumResourcesPerClient int

	// HoldSeconds is how long a selected client stays selected after it stops
	// clearing thresholds. Negative disables the hold entirely. Zero means
	// "use the default", because a zero floor and a zero ceiling describe an
	// unbounded hold rather than the absence of one.
	HoldSeconds int
	// MaximumHoldSeconds bounds the hold. This is the only limit on the cost of
	// a false positive, because once a client is blocked its byte count reports
	// how well the block is working rather than what the client wanted to do.
	MaximumHoldSeconds int
	// ReleaseFactorPercent is the fraction of the selecting thresholds a held
	// client must stay above to remain held.
	ReleaseFactorPercent int

	// ReputationFactor multiplies the request and byte thresholds for clients
	// with good reputation. A multiplier rather than an exemption: a
	// well-behaved client that starts mirroring the site is still caught, it
	// just has to try harder.
	ReputationFactor int64
}

// DefaultConfig returns detect-only defaults. Enforce is deliberately false:
// the thresholds below are a starting point for tuning, not a claim about any
// particular deployment's traffic.
func DefaultConfig() Config {
	return Config{
		Enabled:                           false,
		Enforce:                           false,
		WindowSeconds:                     300,
		EvaluationIntervalSeconds:         10,
		PublishIntervalSeconds:            60,
		MinimumRequests:                   1000,
		MinimumBytes:                      5 << 30,
		MinimumResources:                  500,
		MinimumSections:                   100,
		MaximumResourcesPerSectionPercent: 120,
		MaximumClients:                    20000,
		MaximumResourcesPerClient:         500,
		HoldSeconds:                       600,
		MaximumHoldSeconds:                1200,
		ReleaseFactorPercent:              100,
		ReputationFactor:                  4,
	}
}

// Option customizes a Tracker at construction.
type Option func(*Tracker)

// WithReputation supplies a callback reporting whether a client has good
// reputation. Good-reputation clients get raised thresholds, not an exemption.
func WithReputation(good func(string) bool) Option {
	return func(t *Tracker) { t.goodReputation = good }
}

// WithClock replaces the time source. Tests use it; production does not.
func WithClock(now func() time.Time) Option {
	return func(t *Tracker) {
		if now != nil {
			t.now = now
		}
	}
}

type bucket struct {
	Requests uint64
	Bytes    uint64
}

type resourceEntry struct {
	Key     uint64
	Section uint64
	Seen    time.Time
}

// boundedSet counts the distinct resources a client touched inside the window,
// capped at a fixed size.
//
// When full it evicts the least recently seen entry rather than rejecting the
// new one. Rejecting looks equivalent and is not: a client walking forward
// through a namespace never revisits a resource, so once a rejecting set filled
// nothing would refresh the entries already in it. They would all age out
// together exactly one window later, the client would fall under the resource
// minimum, and detection would collapse on a cycle one window long. Evicting
// the oldest keeps the most recent `limit` resources, which is the quantity the
// minimums are meant to be compared against.
type boundedSet struct {
	entries map[uint64]*list.Element
	order   *list.List
	limit   int
}

func newBoundedSet(limit int) *boundedSet {
	return &boundedSet{entries: make(map[uint64]*list.Element), order: list.New(), limit: limit}
}

// Observe records a resource and the section it belongs to. added is false for
// a refresh of a resource already in the set. evicted reports the section of a
// different resource that had to be dropped to make room, so its reference can
// be released.
func (s *boundedSet) Observe(key, section uint64, now time.Time) (added bool, evicted uint64, didEvict bool) {
	if element, exists := s.entries[key]; exists {
		element.Value.(*resourceEntry).Seen = now
		s.order.MoveToFront(element)
		return false, 0, false
	}
	if s.limit > 0 && len(s.entries) >= s.limit {
		if oldest := s.order.Back(); oldest != nil {
			entry := oldest.Value.(*resourceEntry)
			s.order.Remove(oldest)
			delete(s.entries, entry.Key)
			evicted, didEvict = entry.Section, true
		}
	}
	s.entries[key] = s.order.PushFront(&resourceEntry{Key: key, Section: section, Seen: now})
	return true, evicted, didEvict
}

func (s *boundedSet) Len() int { return len(s.entries) }

// Prune drops entries last seen before cutoff and returns their sections. The
// list stays ordered by Seen, so this walks only the entries it removes.
func (s *boundedSet) Prune(cutoff time.Time) []uint64 {
	var removed []uint64
	for {
		oldest := s.order.Back()
		if oldest == nil {
			return removed
		}
		entry := oldest.Value.(*resourceEntry)
		if !entry.Seen.Before(cutoff) {
			return removed
		}
		s.order.Remove(oldest)
		delete(s.entries, entry.Key)
		removed = append(removed, entry.Section)
	}
}

type clientWindow struct {
	Buckets   map[int64]*bucket
	Resources *boundedSet

	// SectionRefs counts how many retained resources belong to each section.
	//
	// This cannot be an independent capped set. If evicting a resource left its
	// section behind, a client pulling many resources from a few sections would
	// eventually report one section per retained resource, its ratio would
	// drift toward 1.0, and it would look exactly like enumeration. Reference
	// counting makes section cardinality a property of the same retained
	// resource window the ratio is computed from.
	SectionRefs map[uint64]int

	LastSeen    time.Time
	LastPublish time.Time

	// DeferredSince marks when a good-reputation client started sitting between
	// the base and reputation-raised thresholds. Zero when it is not.
	DeferredSince time.Time
	// SelectedSince is what gives the tracker memory of its own actions. A held
	// client is re-decided even when the measurements that selected it have
	// collapsed, because enforcement is what collapsed them.
	SelectedSince time.Time

	Element *list.Element
}

func (c *clientWindow) sectionCount() int { return len(c.SectionRefs) }

func (c *clientWindow) releaseSection(section uint64) {
	if c.SectionRefs[section] <= 1 {
		delete(c.SectionRefs, section)
		return
	}
	c.SectionRefs[section]--
}

// observeResource keeps section cardinality tied to the retained resource set.
// It reports whether admitting this resource evicted a different one.
func (c *clientWindow) observeResource(resource, section uint64, now time.Time) bool {
	added, evicted, didEvict := c.Resources.Observe(resource, section, now)
	if !added {
		return false
	}
	if didEvict {
		c.releaseSection(evicted)
	}
	c.SectionRefs[section]++
	return didEvict
}

func (c *clientWindow) totals() (requests, bytes uint64) {
	for _, values := range c.Buckets {
		requests += values.Requests
		bytes += values.Bytes
	}
	return requests, bytes
}

// Tracker measures clients over a sliding window and selects the ones that
// cross a threshold. It is safe for concurrent use.
type Tracker struct {
	mu     sync.Mutex
	config Config

	clients     map[string]*clientWindow
	clientOrder *list.List

	lastEvaluation      time.Time
	clientEvictions     uint64
	resourceEvictions   uint64
	reputationDeferrals uint64
	longDeferredClients int
	heldClients         int
	decisions           uint64

	goodReputation func(string) bool
	now            func() time.Time

	// holdDisabled is a separate flag rather than a zero duration because a
	// zero floor and a zero ceiling mean an unbounded hold, not the absence of
	// one.
	holdDisabled bool
}

// New creates a Tracker, filling in defaults for unset config values.
func New(cfg Config, options ...Option) *Tracker {
	defaults := DefaultConfig()

	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = defaults.WindowSeconds
	}
	if cfg.EvaluationIntervalSeconds <= 0 {
		cfg.EvaluationIntervalSeconds = defaults.EvaluationIntervalSeconds
	}
	if cfg.PublishIntervalSeconds <= 0 {
		cfg.PublishIntervalSeconds = defaults.PublishIntervalSeconds
	}
	if cfg.MinimumRequests == 0 {
		cfg.MinimumRequests = defaults.MinimumRequests
	}
	if cfg.MinimumBytes == 0 {
		cfg.MinimumBytes = defaults.MinimumBytes
	}
	if cfg.MinimumResources == 0 {
		cfg.MinimumResources = defaults.MinimumResources
	}
	if cfg.MinimumSections == 0 {
		cfg.MinimumSections = defaults.MinimumSections
	}
	if cfg.MaximumResourcesPerSectionPercent <= 0 {
		cfg.MaximumResourcesPerSectionPercent = defaults.MaximumResourcesPerSectionPercent
	}
	if cfg.MaximumClients <= 0 {
		cfg.MaximumClients = defaults.MaximumClients
	}
	if cfg.MaximumResourcesPerClient <= 0 {
		// Sized to the minimum by default: the set only has to be able to hold
		// enough resources to clear the threshold it is compared against.
		cfg.MaximumResourcesPerClient = cfg.MinimumResources
	}
	if cfg.ReleaseFactorPercent <= 0 {
		cfg.ReleaseFactorPercent = defaults.ReleaseFactorPercent
	}
	if cfg.ReputationFactor < 1 {
		cfg.ReputationFactor = defaults.ReputationFactor
	}

	holdDisabled := cfg.HoldSeconds < 0
	if cfg.HoldSeconds <= 0 {
		// Two windows. One is not enough: a client that pauses for a single
		// window would be released on the same cycle that caught it.
		cfg.HoldSeconds = 2 * cfg.WindowSeconds
	}
	if cfg.MaximumHoldSeconds <= 0 {
		// Four windows. This is the worst case imposed on a client blocked in
		// error, so it is deliberately short. A client that is genuinely
		// scraping re-triggers within a window of being released, which costs
		// it far more suppression than it costs the service. There is
		// deliberately no unbounded option: nothing measurable separates a
		// false positive from a suppressed true positive once enforcement has
		// removed the byte evidence, so an unbounded hold would make being
		// wrong permanent.
		cfg.MaximumHoldSeconds = 4 * cfg.WindowSeconds
	}
	if cfg.MaximumHoldSeconds < cfg.HoldSeconds {
		cfg.MaximumHoldSeconds = cfg.HoldSeconds
	}

	t := &Tracker{
		config:       cfg,
		clients:      make(map[string]*clientWindow),
		clientOrder:  list.New(),
		now:          time.Now,
		holdDisabled: holdDisabled,
	}
	for _, option := range options {
		option(t)
	}
	return t
}

// Settings returns the effective configuration, defaults applied.
func (t *Tracker) Settings() Config {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.config
}

// ObserveRequest records one HTTP request from ip for the given host and path.
//
// host and path are hashed immediately and never retained: the tracker counts
// distinct resources and sections, and never needs to read either back.
func (t *Tracker) ObserveRequest(ip, host, path string) {
	if ip == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.config.Enabled {
		return
	}

	resource, section := resourceKeys(host, path)

	now := t.now()
	client := t.client(ip, now)
	if client == nil {
		return
	}
	t.prune(client, now)

	t.bucketFor(client, now).Requests++
	if client.observeResource(resource, section, now) {
		t.resourceEvictions++
	}
	client.LastSeen = now
}

// ObserveBytes records bytes transmitted to ip, as measured on the eBPF egress
// path.
//
// Unlike ObserveRequest this does not create a client. Bytes alone cannot
// select anything - every selection path requires resources and sections, which
// only requests supply - so admitting byte-only clients would fill the map with
// entries that can never be decided on.
func (t *Tracker) ObserveBytes(ip string, bytes uint64) {
	if ip == "" || bytes == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.config.Enabled {
		return
	}

	now := t.now()
	client := t.clients[ip]
	if client == nil {
		return
	}
	t.clientOrder.MoveToFront(client.Element)
	t.prune(client, now)

	t.bucketFor(client, now).Bytes += bytes
	client.LastSeen = now
}

func (t *Tracker) bucketFor(client *clientWindow, now time.Time) *bucket {
	start := now.Truncate(bucketSize).Unix()
	values := client.Buckets[start]
	if values == nil {
		values = &bucket{}
		client.Buckets[start] = values
	}
	return values
}

type match struct {
	Volume bool
	Shape  bool
}

func (m match) over() bool { return m.Volume || m.Shape }

func (m match) path() string {
	switch {
	case m.Volume && m.Shape:
		return "volume+shape"
	case m.Volume:
		return "volume"
	case m.Shape:
		return "shape"
	default:
		return ""
	}
}

// matchThresholds evaluates both selection paths.
//
// The shape path deliberately has no byte floor: breadth is the harm it
// detects, and requiring bytes as well would mean enumeration only registers
// once it also becomes a volume problem. The resources-per-section ceiling is
// what keeps ordinary deep usage out of it.
//
// Reputation raises the request floor on both paths and the byte floor only on
// the path that uses bytes. It does not raise the resource and section floors,
// which describe breadth rather than intensity: a well-behaved client does not
// become entitled to walk more of the namespace.
func matchThresholds(cfg Config, requests, bytes uint64, resources, sections int, factor uint64) match {
	common := requests >= cfg.MinimumRequests*factor &&
		resources >= cfg.MinimumResources &&
		sections >= cfg.MinimumSections
	if !common {
		return match{}
	}
	return match{
		Volume: bytes >= cfg.MinimumBytes*factor,
		Shape:  resourcesPerSectionWithin(cfg.MaximumResourcesPerSectionPercent, resources, sections),
	}
}

func resourcesPerSectionWithin(maximumPercent, resources, sections int) bool {
	return sections > 0 && maximumPercent > 0 &&
		uint64(resources)*100 <= uint64(sections)*uint64(maximumPercent)
}

// Evaluate advances the tracker and returns the clients to act on. It is a
// no-op if called more often than the evaluation interval.
func (t *Tracker) Evaluate() []Decision {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.config.Enabled {
		return nil
	}

	now := t.now()
	if !t.lastEvaluation.IsZero() && now.Sub(t.lastEvaluation) < time.Duration(t.config.EvaluationIntervalSeconds)*time.Second {
		return nil
	}
	t.lastEvaluation = now

	var decisions []Decision
	longDeferred := 0
	held := 0

	for ip, client := range t.clients {
		t.prune(client, now)

		// Two windows of silence. One window would drop a client the instant
		// its last bucket aged out, losing the hold that keeps a blocked client
		// blocked.
		if client.LastSeen.Before(now.Add(-2 * time.Duration(t.config.WindowSeconds) * time.Second)) {
			t.removeClient(ip, client)
			continue
		}

		requests, bytes := client.totals()
		resources := client.Resources.Len()
		sections := client.sectionCount()

		good := t.goodReputation != nil && t.goodReputation(ip)
		factor := int64(1)
		if good {
			factor = t.config.ReputationFactor
		}

		base := matchThresholds(t.config, requests, bytes, resources, sections, 1)
		current := base
		if good {
			current = matchThresholds(t.config, requests, bytes, resources, sections, uint64(factor))
		}

		decision, emit := t.assess(client, assessment{
			base:      base,
			current:   current,
			good:      good,
			requests:  requests,
			resources: resources,
			sections:  sections,
			now:       now,
		}, &longDeferred, &held)
		if !emit {
			continue
		}

		if !client.LastPublish.IsZero() && now.Sub(client.LastPublish) < time.Duration(t.config.PublishIntervalSeconds)*time.Second {
			continue
		}
		client.LastPublish = now

		decision.IP = ip
		decision.Requests = requests
		decision.Bytes = bytes
		decision.Resources = resources
		decision.Sections = sections
		decision.GoodReputation = good
		decision.ThresholdFactor = factor
		decisions = append(decisions, decision)
		t.decisions++
	}

	t.longDeferredClients = longDeferred
	t.heldClients = held
	return decisions
}

type assessment struct {
	base      match
	current   match
	good      bool
	requests  uint64
	resources int
	sections  int
	now       time.Time
}

// assess decides what happens to one client this evaluation: nothing, a fresh
// selection, or a continued hold. It reports the decision and whether to emit
// it.
func (t *Tracker) assess(client *clientWindow, a assessment, longDeferred, held *int) (Decision, bool) {
	if client.SelectedSince.IsZero() {
		if !a.base.over() {
			client.DeferredSince = time.Time{}
			return Decision{}, false
		}
		if a.good && !a.current.over() {
			// Over the base thresholds but under the reputation-raised ones.
			// Counted and timed, because a client sitting here for a full
			// window is a tuning signal rather than an outcome.
			t.reputationDeferrals++
			if client.DeferredSince.IsZero() {
				client.DeferredSince = a.now
			}
			if a.now.Sub(client.DeferredSince) >= time.Duration(t.config.WindowSeconds)*time.Second {
				*longDeferred++
			}
			return Decision{}, false
		}
		client.DeferredSince = time.Time{}
		if !t.holdDisabled {
			client.SelectedSince = a.now
		}
		return Decision{Path: a.current.path()}, true
	}

	if a.current.over() {
		// Still clearing on its own merits, so this is a fresh crossing rather
		// than a hold. Restarting the clock keeps the hold bounds measuring
		// only the time spent held after the client stopped clearing.
		client.SelectedSince = a.now
		return Decision{Path: a.current.path()}, true
	}

	// Release is judged on requests and breadth, never on bytes. A blocked
	// client is not being served, so its byte count reports how well the block
	// is working rather than whether the client has stopped. Requests and
	// breadth still originate with the client, so they are what can honestly
	// say it has backed off.
	//
	// Every leg has to hold. An OR at a fraction of the threshold looks safer
	// and is not: requests is the least selective leg, so on its own it would
	// pin ordinary clients in the hold and leave the ceiling to do all the work
	// of releasing them. Shape is deliberately not a release leg, because the
	// ratio can recover before the retained resource and section sets have aged
	// out.
	release := t.config.ReleaseFactorPercent
	stillActive := a.requests >= t.config.MinimumRequests*uint64(release)/100 &&
		a.resources >= t.config.MinimumResources*release/100 &&
		a.sections >= t.config.MinimumSections*release/100

	heldFor := a.now.Sub(client.SelectedSince)
	maximumHold := t.config.MaximumHoldSeconds
	if a.good && maximumHold > t.config.HoldSeconds {
		// Good reputation is the one signal arguing that a selection was a
		// mistake, so those clients leave at the floor rather than the ceiling.
		maximumHold = t.config.HoldSeconds
	}

	beyondMaximum := heldFor >= time.Duration(maximumHold)*time.Second
	beyondMinimum := heldFor >= time.Duration(t.config.HoldSeconds)*time.Second
	if beyondMaximum || (beyondMinimum && !stillActive) {
		client.SelectedSince = time.Time{}
		client.DeferredSince = time.Time{}
		return Decision{}, false
	}

	*held++
	return Decision{Held: true}, true
}

// Enforcing reports whether this detector's own configuration turns decisions
// into blocks. It says nothing about the analyzer-wide enforcement state, which
// is enforced at the point commands are issued rather than here.
func (t *Tracker) Enforcing() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.config.Enabled && t.config.Enforce
}

// Stats returns a snapshot of tracker health.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Stats{
		TrackedClients:      len(t.clients),
		Decisions:           t.decisions,
		ClientEvictions:     t.clientEvictions,
		ResourceEvictions:   t.resourceEvictions,
		ReputationDeferrals: t.reputationDeferrals,
		LongDeferredClients: t.longDeferredClients,
		HeldClients:         t.heldClients,
	}
}

func (t *Tracker) client(ip string, now time.Time) *clientWindow {
	if client := t.clients[ip]; client != nil {
		t.clientOrder.MoveToFront(client.Element)
		return client
	}
	if len(t.clients) >= t.config.MaximumClients {
		if oldest := t.clientOrder.Back(); oldest != nil {
			oldestIP := oldest.Value.(string)
			t.removeClient(oldestIP, t.clients[oldestIP])
			t.clientEvictions++
		}
	}
	client := &clientWindow{
		Buckets:     make(map[int64]*bucket),
		Resources:   newBoundedSet(t.config.MaximumResourcesPerClient),
		SectionRefs: make(map[uint64]int),
		LastSeen:    now,
	}
	client.Element = t.clientOrder.PushFront(ip)
	t.clients[ip] = client
	return client
}

func (t *Tracker) removeClient(ip string, client *clientWindow) {
	if client != nil && client.Element != nil {
		t.clientOrder.Remove(client.Element)
	}
	delete(t.clients, ip)
}

func (t *Tracker) prune(client *clientWindow, now time.Time) {
	cutoff := now.Add(-time.Duration(t.config.WindowSeconds) * time.Second)
	for start := range client.Buckets {
		if !time.Unix(start, 0).Add(bucketSize).After(cutoff) {
			delete(client.Buckets, start)
		}
	}
	for _, section := range client.Resources.Prune(cutoff) {
		client.releaseSection(section)
	}
}

// resourceKeys reduces a request to the two hashes the tracker counts: the
// resource (host plus path) and the section it belongs to (host plus the first
// path segment).
//
// Sections are what let the two selection paths tell different clients apart. A
// mirror or CI job pulls many resources from a handful of sections; enumeration
// walks the namespace and touches roughly one resource per section. Neither the
// host nor the path is retained.
func resourceKeys(host, path string) (resource, section uint64) {
	host = strings.ToLower(host)
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	return hash64(host, path), hash64(host, firstSegment(path))
}

// firstSegment returns the leading path segment, with its separator, so that
// "/a/b" and "/a/c" share a section while "/a" and "/b" do not.
func firstSegment(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if idx := strings.IndexByte(trimmed, '/'); idx >= 0 {
		return "/" + trimmed[:idx]
	}
	return "/" + trimmed
}

func hash64(parts ...string) uint64 {
	h := fnv.New64a()
	for i, part := range parts {
		if i > 0 {
			// A separator keeps ("ab", "c") and ("a", "bc") distinct, which
			// matters because a host and a path are concatenated here.
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(part))
	}
	return h.Sum64()
}
