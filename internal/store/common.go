package store

import (
	"sync/atomic"
	"time"
)

type CollType int

type Coll struct {
	T    CollType
	Name string
}

const (
	COLL_TYPE_TR CollType = iota
	COLL_TYPE_CEP
	COLL_TYPE_OTHER
)

// DeadlineCounter is not intent for concurrently usage
type DeadlineCounter struct {
	C        chan bool
	limit    uint64
	ops      atomic.Uint64
	done     chan bool
	timer    *time.Timer
	deadline time.Duration
	stopped  bool
}

func NewDeadlineCounter(limit uint64, deadline time.Duration) *DeadlineCounter {
	counter := DeadlineCounter{
		C:        make(chan bool, 1),
		limit:    limit,
		ops:      atomic.Uint64{},
		done:     make(chan bool, 1),
		deadline: deadline,
		timer:    time.NewTimer(deadline),
		stopped:  false,
	}
	go func() {
		for {
			select {
			case <-counter.done:
				counter.stopTimer()
				return
			case <-counter.timer.C:
				counter.C <- true
				return
			default:
				ops := counter.ops.Load()
				if ops >= limit {
					counter.C <- true
					counter.stopTimer()
					return
				}
			}
		}
	}()
	return &counter
}

func (c *DeadlineCounter) Add(delta uint64) uint64 {
	return c.ops.Add(delta)
}

func (c *DeadlineCounter) Value() uint64 {
	return c.ops.Load()
}

func (c *DeadlineCounter) Stop() {
	if !c.stopped {
		c.stopTimer()
		c.stopped = true
		c.done <- true
		if len(c.C) > 0 {
			<-c.C
		}
	}
}

func (c *DeadlineCounter) stopTimer() {
	if !c.timer.Stop() {
		if len(c.timer.C) > 0 {
			<-c.timer.C
		}
	}
}
