package aidetection

const minRingGrowth = 8

type eventRing[T any] struct {
	buf   []T
	head  int
	size  int
	limit int
}

func newEventRing[T any](limit int) eventRing[T] {
	return eventRing[T]{limit: max(limit, 1)}
}

func (r *eventRing[T]) Len() int {
	return r.size
}

func (r *eventRing[T]) At(i int) *T {
	return &r.buf[r.physical(i)]
}

func (r *eventRing[T]) physical(i int) int {
	p := r.head + i
	if p >= len(r.buf) {
		p -= len(r.buf)
	}
	return p
}

func (r *eventRing[T]) PushBack(v T) {
	if r.size == r.limit {
		r.buf[r.head] = v
		r.head = r.physical(1)
		return
	}
	if r.size == len(r.buf) {
		r.grow()
	}
	r.buf[r.physical(r.size)] = v
	r.size++
}

func (r *eventRing[T]) grow() {
	capacity := min(max(2*len(r.buf), minRingGrowth), r.limit)
	grown := make([]T, capacity)
	r.copyTo(grown)
	r.buf = grown
	r.head = 0
}

func (r *eventRing[T]) copyTo(dst []T) int {
	if r.size == 0 {
		return 0
	}
	end := r.head + r.size
	if end <= len(r.buf) {
		return copy(dst, r.buf[r.head:end])
	}
	n := copy(dst, r.buf[r.head:])
	return n + copy(dst[n:], r.buf[:end-len(r.buf)])
}

func (r *eventRing[T]) DropFront(n int) {
	n = min(n, r.size)
	var zero T
	for range n {
		r.buf[r.head] = zero
		r.head = r.physical(1)
	}
	r.size -= n
	if r.size == 0 {
		r.head = 0
	}
}

func (r *eventRing[T]) Slice() []T {
	out := make([]T, r.size)
	r.copyTo(out)
	return out
}
