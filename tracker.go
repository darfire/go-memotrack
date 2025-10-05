package main

import (
	"cmp"
	"fmt"
	"log"
	"log/slog"
	"math"
	"slices"
	"time"
)

type SingleStackHistory struct {
	Count     uint64
	Timestamp int64
}

type StackHistory struct {
	Stacks    map[uint32]uint64
	Timestamp int64
}

type RingBuf[T any] struct {
	buf []T
	cap int
	pos int
	len int
}

func NewRingBuf[T any](cap int) RingBuf[T] {
	return RingBuf[T]{
		buf: make([]T, cap),
		cap: cap,
		pos: 0,
		len: 0,
	}
}

func (rb *RingBuf[T]) Add(item T) {
	rb.buf[rb.pos] = item
	rb.pos = (rb.pos + 1) % rb.cap
	if rb.len < rb.cap {
		rb.len++
	}
}

func (rb *RingBuf[T]) Get(idx int) T {
	if idx < 0 || idx >= rb.len {
		var zero T
		return zero
	}
	return rb.buf[(rb.pos-rb.len+idx+rb.cap)%rb.cap]
}

func (rb *RingBuf[T]) Len() int {
	return rb.len
}

func (rb *RingBuf[T]) ToSlice() []T {
	slice := make([]T, rb.len)

	start := (rb.pos - rb.len + rb.cap) % rb.cap

	end := rb.pos

	if start >= end {
		slice = append(slice, rb.buf[start:rb.cap]...)
		slice = append(slice, rb.buf[0:end]...)
	} else {
		slice = append(slice, rb.buf[start:end]...)
	}

	return slice
}

type AllocObject struct {
	AllocTstamp uint64
	Address     int64
	StackId     uint32
	Pid         int
	ObjectType  uint8
}

type AllocationTracker struct {
	// a map of current allocated objects
	Objects map[int64]AllocObject
	// for each stack id we've seen, the associated instruction addresses
	Stacks map[uint32][]uint64
	// the defined objects
	Specs map[uint8]*ObjectSpec
	// where we stack the history of the allocate object counts, per stack id
	History RingBuf[StackHistory]
	// last time we added to History
	LastTime uint64
	// a callback to fetch stack addresses, by stack id
	LookupStack      LookupStackCb
	HistoryIntervalS uint64
}

type LookupStackCb func(uint32) []uint64

type TrackerOptions struct {
	LookupStack       LookupStackCb
	Specs             []ObjectSpec
	HistoryIntervalS  uint64
	MaxHistoryBuckets uint64
}

func NewAllocationTracker(options TrackerOptions) AllocationTracker {
	specs := make(map[uint8]*ObjectSpec)

	for _, s := range options.Specs {
		specs[s.Type] = &s
	}

	return AllocationTracker{
		Objects:          make(map[int64]AllocObject),
		Stacks:           make(map[uint32][]uint64),
		LastTime:         0,
		Specs:            specs,
		LookupStack:      options.LookupStack,
		History:          NewRingBuf[StackHistory](int(options.MaxHistoryBuckets)),
		HistoryIntervalS: options.HistoryIntervalS,
	}
}

func (tracker *AllocationTracker) Add(alloc AllocObject) {
	// slog.Debug("adding alloc", "address", alloc.Address, "stackId", alloc.StackId)
	tracker.Objects[alloc.Address] = alloc
	tracker.LastTime = max(tracker.LastTime, alloc.AllocTstamp)
}

func (tracker *AllocationTracker) Remove(address int64) {
	if _, ok := tracker.Objects[address]; !ok {
		slog.Error("object not found", "address", address)
		return
	}

	// slog.Debug("removing alloc", "address", address)
	delete(tracker.Objects, address)
}

func (tracker *AllocationTracker) HasStack(stackId uint32) bool {
	_, ok := tracker.Stacks[stackId]
	return ok
}

func (tracker *AllocationTracker) AddStack(stackId uint32, ips []uint64) {
	tracker.Stacks[stackId] = ips
}

func (tracker *AllocationTracker) MaybeAddStack(stackId int64, lookup_stack func(int64) []uint64) {
}

func (tracker *AllocationTracker) PrintStatus() {
	log.Printf("%d allocations, %d stacks", len(tracker.Objects), len(tracker.Stacks))
}

type StackStats struct {
	countActive uint32
	stackId     uint32
	objectSpec  *ObjectSpec
	pow2Hist    []uint64
	ips         []uint64
	pid         int
}

func (s *StackStats) updateHist(delta uint64) {
	if delta == 0 {
		return
	}

	// Calculate the base-2 logarithm of delta.
	log2Delta := uint64(math.Log2(float64(delta)))

	// increase the histogram size
	if len(s.pow2Hist) <= int(log2Delta) {
		newHist := make([]uint64, log2Delta+1)
		copy(newHist, s.pow2Hist)
		s.pow2Hist = newHist
	}

	// Increment the count for this power of 2.
	s.pow2Hist[log2Delta]++
}

func (tracker *AllocationTracker) AddEvent(event ebpfEventT) {
	// slog.Debug("received event", "type", event.Type, "addr", event.Addr, "stackId", event.StackId, "pid", event.Pid)

	if event.Type == 0 {
		tracker.Add(AllocObject{
			AllocTstamp: event.Tstamp,
			Address:     event.Addr,
			StackId:     event.StackId,
			ObjectType:  event.ObjectType,
			Pid:         int(event.Pid),
		})

		if !tracker.HasStack(event.StackId) {
			ips := tracker.LookupStack(event.StackId)
			tracker.AddStack(event.StackId, ips)
		}
	} else {
		tracker.Remove(event.Addr)
	}

	// slog.Debug("after event handle", "objects", len(tracker.Objects), "stacks", len(tracker.Stacks))
}

func (tracker *AllocationTracker) PushHistory() {
	counts := make(map[uint32]uint64)

	for _, alloc := range tracker.Objects {
		_, ok := counts[alloc.StackId]

		if !ok {
			counts[alloc.StackId] = 1
		} else {
			counts[alloc.StackId] += 1
		}
	}

	tracker.History.Add(StackHistory{
		Stacks:    counts,
		Timestamp: time.Now().Unix(),
	})
}

const (
	CmdNop = iota
	CmdAddEvent
	CmdGetAllStats
	CmdGetSingleStats
	CmdGetTrends
	CmdExit
)

type TrackerRequest struct {
	requestType  uint8
	responseChan chan TrackerResponse
	payload      interface{}
}

type AllStatsPayload struct {
	stacks  []*StackStats
	history []StackHistory
}

type SingleStatsPayload struct {
	stack   *StackStats
	history []SingleStackHistory
}

type TrackerResponse struct {
	requestType uint8
	payload     interface{}
	err         error
}

func NewTrackerResponse(requestType uint8, payload interface{}, err error) TrackerResponse {
	return TrackerResponse{
		requestType,
		payload,
		err,
	}
}

func NewTrackerRequest(requestType uint8, payload interface{}, responseChan chan TrackerResponse) TrackerRequest {
	return TrackerRequest{
		requestType:  requestType,
		responseChan: responseChan,
		payload:      payload,
	}
}

func (tracker *AllocationTracker) Run(
	requestChan chan TrackerRequest,
	stopper chan interface{},
) {
	timer := time.NewTimer(time.Duration(tracker.HistoryIntervalS) * time.Second)
	defer timer.Stop()

outerLoop:
	for {
		select {
		case request := <-requestChan:
			// slog.Debug(fmt.Sprintf("received request: %v", request))
			switch request.requestType {
			case CmdAddEvent:
				tracker.AddEvent(request.payload.(ebpfEventT))
			case CmdGetAllStats:
				stats := tracker.ComputeStats()
				history := tracker.GetTrends()
				payload := AllStatsPayload{
					stacks:  stats,
					history: history,
				}
				request.responseChan <- NewTrackerResponse(request.requestType, payload, nil)
			case CmdGetSingleStats:
				stackId := request.payload.(uint32)
				history := tracker.GetStackHistory(stackId)
				stack, err := tracker.GetStackStats(stackId)
				payload := SingleStatsPayload{
					stack:   &stack,
					history: history,
				}
				request.responseChan <- NewTrackerResponse(request.requestType, payload, err)
			case CmdGetTrends:
				trends := tracker.GetTrends()
				request.responseChan <- NewTrackerResponse(request.requestType, trends, nil)
			case CmdNop:
				// nothing
			case CmdExit:
				break outerLoop
			}
		case <-timer.C:
			tracker.PushHistory()
		case <-stopper:
			break outerLoop
		}
	}
}

func (tracker *AllocationTracker) ComputeStats() []*StackStats {
	stats := make(map[uint32]*StackStats)

	for _, alloc := range tracker.Objects {
		if !tracker.HasStack(alloc.StackId) {
			slog.Warn("stack not found", "stackId", alloc.StackId)
			continue
		}

		if _, ok := stats[alloc.StackId]; !ok {
			ips := tracker.Stacks[alloc.StackId]

			spec, ok := tracker.Specs[alloc.ObjectType]

			if !ok {
				continue
			}

			stats[alloc.StackId] = &StackStats{
				countActive: 1,
				stackId:     alloc.StackId,
				objectSpec:  spec,
				pow2Hist:    make([]uint64, 16),
				ips:         ips,
				pid:         alloc.Pid,
			}
		} else {
			stats[alloc.StackId].countActive += 1
		}

		stats[alloc.StackId].updateHist((tracker.LastTime - alloc.AllocTstamp) / 1000000000.)
	}

	sortedByCount := make([]*StackStats, 0, len(stats))
	for _, s := range stats {
		sortedByCount = append(sortedByCount, s)
	}

	slices.SortFunc(sortedByCount, func(a, b *StackStats) int {
		return -cmp.Compare(a.countActive, b.countActive)
	})

	return sortedByCount
}

func (tracker *AllocationTracker) GetStackStats(stackId uint32) (StackStats, error) {
	if !tracker.HasStack(stackId) {
		return StackStats{}, fmt.Errorf("stack %d not found", stackId)
	}

	var stats *StackStats

	for _, alloc := range tracker.Objects {
		if alloc.StackId != stackId {
			continue
		}

		if stats == nil {
			ips := tracker.Stacks[alloc.StackId]

			spec, ok := tracker.Specs[alloc.ObjectType]

			if !ok {
				panic(fmt.Sprintf("stack %d not found in specs", stackId))
			}

			stats = &StackStats{
				countActive: 1,
				stackId:     alloc.StackId,
				pid:         alloc.Pid,
				objectSpec:  spec,
				pow2Hist:    make([]uint64, 16),
				ips:         ips,
			}
		} else {
			stats.countActive += 1
		}

		stats.updateHist((tracker.LastTime - alloc.AllocTstamp) / 1000000000.)
	}

	return *stats, nil
}

func (tracker *AllocationTracker) GetTrends() []StackHistory {
	return tracker.History.ToSlice()
}

func (tracker *AllocationTracker) GetStackHistory(stackId uint32) []SingleStackHistory {
	return ExtractSingleHistory(tracker.History.ToSlice(), stackId)
}

func ExtractSingleHistory(history []StackHistory, stackId uint32) []SingleStackHistory {
	response := make([]SingleStackHistory, 0, len(history))

	for _, h := range history {
		if count, ok := h.Stacks[stackId]; ok {
			response = append(response, SingleStackHistory{
				Count:     count,
				Timestamp: h.Timestamp,
			})
		} else if len(response) > 0 {
			response = append(response, SingleStackHistory{
				Count:     0,
				Timestamp: h.Timestamp,
			})
		}
	}

	return response
}
