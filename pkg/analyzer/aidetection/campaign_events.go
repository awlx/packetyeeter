package aidetection

import "time"

type campaignEvent struct {
	campaignSignal
	highWater time.Time
}

type campaignEvents struct {
	ring      eventRing[campaignEvent]
	highWater time.Time
	maxLag    time.Duration
}

func newCampaignEvents(maxEvents int) campaignEvents {
	return campaignEvents{ring: newEventRing[campaignEvent](maxEvents + 1)}
}

func (e *campaignEvents) Len() int {
	return e.ring.Len()
}

func (e *campaignEvents) At(i int) *campaignSignal {
	return &e.ring.At(i).campaignSignal
}

func (e *campaignEvents) Push(signal campaignSignal) {
	if e.ring.Len() == 0 || signal.timestamp.After(e.highWater) {
		e.highWater = signal.timestamp
	}
	if lag := e.highWater.Sub(signal.timestamp); lag > e.maxLag {
		e.maxLag = lag
	}
	e.ring.PushBack(campaignEvent{campaignSignal: signal, highWater: e.highWater})
}

func (e *campaignEvents) TrimTo(maxEvents int) {
	if excess := e.ring.Len() - maxEvents; excess > 0 {
		e.ring.DropFront(excess)
	}
}

func (e *campaignEvents) PruneBefore(cutoff time.Time) (firstSeen, lastSeen time.Time, ok bool) {
	stop, removed, firstSeen := e.scanExpiredPrefix(cutoff)
	e.compactPrefix(stop, removed, cutoff)
	if e.ring.Len() == 0 {
		e.highWater = time.Time{}
		e.maxLag = 0
		return time.Time{}, time.Time{}, false
	}
	return firstSeen, e.latestTimestamp(), true
}

func (e *campaignEvents) scanExpiredPrefix(cutoff time.Time) (stop, removed int, earliest time.Time) {
	haveEarliest := false
	for i := range e.ring.Len() {
		ev := e.ring.At(i)
		if haveEarliest && !ev.highWater.Add(-e.maxLag).Before(earliest) {
			return i, removed, earliest
		}
		if ev.timestamp.Before(cutoff) {
			removed++
			continue
		}
		if !haveEarliest || ev.timestamp.Before(earliest) {
			earliest = ev.timestamp
			haveEarliest = true
		}
	}
	return e.ring.Len(), removed, earliest
}

func (e *campaignEvents) compactPrefix(stop, removed int, cutoff time.Time) {
	if removed == 0 {
		return
	}
	write := stop - 1
	for read := stop - 1; read >= 0; read-- {
		ev := e.ring.At(read)
		if ev.timestamp.Before(cutoff) {
			continue
		}
		if read != write {
			*e.ring.At(write) = *ev
		}
		write--
	}
	e.ring.DropFront(removed)
}

func (e *campaignEvents) latestTimestamp() time.Time {
	last := e.ring.Len() - 1
	latest := e.ring.At(last).timestamp
	for i := last - 1; i >= 0; i-- {
		ev := e.ring.At(i)
		if !ev.highWater.After(latest) {
			break
		}
		if !ev.timestamp.Before(latest) {
			latest = ev.timestamp
		}
	}
	return latest
}
