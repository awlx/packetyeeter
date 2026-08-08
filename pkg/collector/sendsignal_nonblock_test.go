package collector

import (
	"sync"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"

	"github.com/sirupsen/logrus"
)

// sendSignal is called from synchronous SPOE callbacks, so it must never block
// even when the ring buffer is full and many producers hammer it concurrently.
// The previous implementation dropped the oldest entry and then did an
// unconditional blocking send, which deadlocked a caller when other producers
// refilled the freed slot first. These tests lock in the non-blocking contract.

func newQueueTestCollector(queueSize int) *Collector {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return &Collector{
		Logger:      logger,
		signalQueue: make(chan *apiv1.Signal, queueSize),
	}
}

func TestSendSignal_NeverBlocksOnFullQueue(t *testing.T) {
	c := newQueueTestCollector(4)
	// Fill the queue to capacity.
	for i := 0; i < 4; i++ {
		c.signalQueue <- &apiv1.Signal{Id: "seed"}
	}

	done := make(chan struct{})
	go func() {
		// Many more sends than capacity, all against a full queue.
		for i := 0; i < 1000; i++ {
			c.sendSignal(&apiv1.Signal{Id: "new"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sendSignal blocked on a full queue")
	}

	if len(c.signalQueue) > cap(c.signalQueue) {
		t.Fatalf("queue overflowed capacity: len=%d cap=%d", len(c.signalQueue), cap(c.signalQueue))
	}
}

func TestSendSignal_ConcurrentProducersNeverBlock(t *testing.T) {
	c := newQueueTestCollector(8)
	for i := 0; i < 8; i++ {
		c.signalQueue <- &apiv1.Signal{Id: "seed"}
	}

	const producers = 16
	const perProducer = 500
	var wg sync.WaitGroup
	wg.Add(producers)
	for p := 0; p < producers; p++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				c.sendSignal(&apiv1.Signal{Id: "concurrent"})
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent producers blocked in sendSignal")
	}

	if got := len(c.signalQueue); got > cap(c.signalQueue) {
		t.Fatalf("queue overflowed capacity: len=%d cap=%d", got, cap(c.signalQueue))
	}
}

func TestSendSignal_DeliversWhenQueueHasRoom(t *testing.T) {
	c := newQueueTestCollector(4)
	c.sendSignal(&apiv1.Signal{Id: "a"})
	if len(c.signalQueue) != 1 {
		t.Fatalf("expected 1 queued signal, got %d", len(c.signalQueue))
	}
	got := <-c.signalQueue
	if got.Id != "a" {
		t.Fatalf("expected signal id 'a', got %q", got.Id)
	}
}
