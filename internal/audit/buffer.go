/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package audit

import (
	"strings"
	"sync"
)

// RingBuffer is a fixed-capacity circular buffer of audit events.
// Thread-safe for concurrent Push and Query operations.
//
// Query is O(n) on buffer capacity — it scans all entries under a read lock.
// At the default capacity of 10,000 this is fast. Setting bufferSize to 100K
// via ButlerConfig means every query scans 100K entries.
type RingBuffer struct {
	mu      sync.RWMutex
	entries []Event
	head    int
	count   int
	cap     int
}

// NewRingBuffer creates a ring buffer with the given capacity.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 100 {
		capacity = 100
	}
	return &RingBuffer{
		entries: make([]Event, capacity),
		cap:     capacity,
	}
}

// Push adds an event to the buffer, overwriting the oldest if full.
func (b *RingBuffer) Push(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.head] = e
	b.head = (b.head + 1) % b.cap
	if b.count < b.cap {
		b.count++
	}
}

// Query returns events matching the filter options and the total count of matches.
// Events are returned in reverse chronological order (newest first).
func (b *RingBuffer) Query(opts QueryOpts) ([]Event, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.count == 0 {
		return nil, 0
	}

	// Iterate in reverse chronological order (newest first)
	var matched []Event
	total := 0

	for i := 0; i < b.count; i++ {
		idx := (b.head - 1 - i + b.cap) % b.cap
		e := b.entries[idx]

		if !matchesFilter(e, opts) {
			continue
		}

		total++

		// Skip entries before offset
		if total <= opts.Offset {
			continue
		}

		// Collect up to limit
		if opts.Limit > 0 && len(matched) >= opts.Limit {
			continue // keep counting total
		}

		matched = append(matched, e)
	}

	return matched, total
}

func matchesFilter(e Event, opts QueryOpts) bool {
	if opts.User != "" && !strings.EqualFold(e.User, opts.User) {
		return false
	}
	if opts.Action != "" && e.Action != opts.Action {
		return false
	}
	if opts.ResourceType != "" && !strings.EqualFold(e.ResourceType, opts.ResourceType) {
		return false
	}
	if opts.Success != nil && e.Success != *opts.Success {
		return false
	}
	if opts.TeamRef != "" && e.TeamRef != opts.TeamRef {
		return false
	}
	if !opts.From.IsZero() && e.Timestamp.Before(opts.From) {
		return false
	}
	if !opts.To.IsZero() && e.Timestamp.After(opts.To) {
		return false
	}
	return true
}
