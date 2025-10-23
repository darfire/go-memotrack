package main

import (
	"cmp"
	"fmt"
	"log"
	"log/slog"
	"math"
	"slices"
)

const NS_IN_SEC = 1000000000

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

func (rb *RingBuf[T]) Get(idx int) (T, bool) {
	if idx < 0 || idx >= rb.len {
		var zero T
		return zero, false
	}
	return rb.buf[(rb.pos-rb.len+idx+rb.cap)%rb.cap], true
}

func (rb *RingBuf[T]) GetLast() (T, bool) {
	return rb.Get(rb.len - 1)
}

func (rb *RingBuf[T]) Len() int {
	return rb.len
}

func (rb *RingBuf[T]) ToSlice() []T {
	slice := make([]T, 0, rb.len)

	if rb.len == 0 {
		return slice
	}

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
	Pid         uint32
	Tgid        uint32
	ProbeId     uint16
}

type StatsBucket struct {
	TimeStamp uint64
	Counts    map[string]int64
}

const (
	AllocatorProbe = iota
	DeallocatorProbe
	ReferenceProbe
)

type ProbeSpec struct {
	probeId    uint16
	symbolName string
	probeType  uint8
	objectSpec *ObjectSpec
}

type AllocationTracker struct {
	// a map of current allocated objects
	ActiveObjects map[int64]AllocObject
	// for each stack id we've seen, the associated instruction addresses
	Stacks map[uint32][]uint64
	// the defined objects
	ObjectSpecs map[string]*ObjectSpec
	ProbeSpecs  map[uint16]*ProbeSpec
	// last time we added to History
	LastTime uint64
	// a callback to fetch stack addresses, by stack id
	LookupStack      LookupStackCb
	SampleIntervalNs uint64
	Stats            RingBuf[*StatsBucket]
}

type LookupStackCb func(uint32) []uint64

type TrackerOptions struct {
	LookupStack     LookupStackCb
	ObjectSpecs     []ObjectSpec
	ProbeSpecs      []ProbeSpec
	SampleIntervalS uint64
	MaxStatsBuckets uint64
}

func NewAllocationTracker(options TrackerOptions) AllocationTracker {
	objectSpecs := make(map[string]*ObjectSpec)

	probeSpecs := make(map[uint16]*ProbeSpec)

	for _, s := range options.ObjectSpecs {
		objectSpecs[s.Name] = &s
	}

	for _, s := range options.ProbeSpecs {
		probeSpecs[s.probeId] = &s
	}

	return AllocationTracker{
		ActiveObjects:    make(map[int64]AllocObject),
		Stacks:           make(map[uint32][]uint64),
		LastTime:         0,
		ObjectSpecs:      objectSpecs,
		ProbeSpecs:       probeSpecs,
		LookupStack:      options.LookupStack,
		SampleIntervalNs: options.SampleIntervalS * NS_IN_SEC,
		Stats:            NewRingBuf[*StatsBucket](int(options.MaxStatsBuckets)),
	}
}

func (tracker *AllocationTracker) Add(alloc AllocObject) {
	// slog.Debug("adding alloc", "address", alloc.Address, "stackId", alloc.StackId)
	tracker.ActiveObjects[alloc.Address] = alloc
	tracker.LastTime = max(tracker.LastTime, alloc.AllocTstamp)
}

func (tracker *AllocationTracker) Remove(address int64) (AllocObject, bool) {
	alloc, ok := tracker.ActiveObjects[address]

	if !ok {
		slog.Warn("object not found", "address", fmt.Sprintf("%x", address))
		return AllocObject{}, false
	}

	// slog.Debug("removing alloc", "address", address)
	delete(tracker.ActiveObjects, address)

	return alloc, true
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
	log.Printf("%d allocations, %d stacks", len(tracker.ActiveObjects), len(tracker.Stacks))
}

type StackStats struct {
	countActive uint32
	stackId     uint32
	objectSpec  *ObjectSpec
	pow2Hist    []uint64
	ips         []uint64
	pid         uint32
	tgid        uint32
	err         error
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
	// slog.Debug("received event", "addr", event.Addr, "stackId", event.StackId, "pidtgid", event.PidTgid, "tstamp", event.Tstamp)

	probeSpec, ok := tracker.ProbeSpecs[event.ProbeId]

	if !ok {
		log.Printf("unknown probe id: %d", event.ProbeId)
		return
	}

	pid := uint32((event.PidTgid >> 32) & 0xffffffff)
	tgid := uint32(event.PidTgid & 0xffffffff)

	switch probeSpec.probeType {
	case AllocatorProbe:
		tracker.Add(AllocObject{
			AllocTstamp: event.Tstamp,
			Address:     event.Addr,
			StackId:     event.StackId,
			ProbeId:     event.ProbeId,
			Pid:         pid,
			Tgid:        tgid,
		})

		if !tracker.HasStack(event.StackId) {
			ips := tracker.LookupStack(event.StackId)
			tracker.AddStack(event.StackId, ips)
		}

		tracker.IncStats(event.Tstamp, fmt.Sprintf("stack:%d:alloc", event.StackId))
	case DeallocatorProbe:
		alloc, ok := tracker.Remove(event.Addr)
		if !ok {
			slog.Warn("object not found", "address", fmt.Sprintf("%x", event.Addr))
			return
		} else {
			tracker.IncStats(event.Tstamp, fmt.Sprintf("stack:%d:free", alloc.StackId))
		}
	case ReferenceProbe:
		tracker.IncStats(event.Tstamp, fmt.Sprintf("reference:%s", probeSpec.symbolName))
	default:
		panic(fmt.Sprintf("unknown probe type: %d", probeSpec.probeType))
	}

	// slog.Debug("after event handle", "objects", len(tracker.Objects), "stacks", len(tracker.Stacks))
}

func (tracker *AllocationTracker) GetStatsBucket(tstamp uint64) *StatsBucket {
	startInterval := tstamp - (tstamp % tracker.SampleIntervalNs)

	// log.Printf("Getting stats bucket for tstamp %d, start interval %d", tstamp, startInterval)

	last, ok := tracker.Stats.GetLast()

	if !ok || last.TimeStamp != startInterval {
		last = &StatsBucket{
			TimeStamp: startInterval,
			Counts:    make(map[string]int64),
		}

		log.Printf("creating new stats bucket: %d, len: %d", startInterval, tracker.Stats.Len())

		tracker.Stats.Add(last)
	}

	return last
}

func (tracker *AllocationTracker) IncStats(tstamp uint64, key string) {
	last := tracker.GetStatsBucket(tstamp)

	last.Counts[key]++
}

func (tracker *AllocationTracker) DecStats(tstamp uint64, key string) {
	last := tracker.GetStatsBucket(tstamp)

	last.Counts[key]--
}

const (
	CmdNop = iota
	CmdAddEvent
	CmdAddReferenceEvent
	CmdGetAllStats
	CmdGetSingleStats
	CmdGetTraces
	CmdExit
)

type TrackerRequest struct {
	requestType  uint8
	responseChan chan TrackerResponse
	payload      interface{}
}

type SingleStatsPayload struct {
	stack *StackStats
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
outerLoop:
	for {
		select {
		case request := <-requestChan:
			// slog.Debug(fmt.Sprintf("received request: %v", request))
			switch request.requestType {
			case CmdAddEvent:
				tracker.AddEvent(request.payload.(ebpfEventT))
			case CmdGetAllStats:
				payload := tracker.GetStacks()
				request.responseChan <- NewTrackerResponse(request.requestType, payload, nil)
			case CmdGetSingleStats:
				stackId := request.payload.(uint32)
				stack := tracker.GetStackStats(stackId)
				request.responseChan <- NewTrackerResponse(request.requestType, stack, nil)
			case CmdGetTraces:
				traces := tracker.GetTraces()
				request.responseChan <- NewTrackerResponse(request.requestType, traces, nil)
			case CmdNop:
				// nothing
			case CmdExit:
				break outerLoop
			}
		case <-stopper:
			break outerLoop
		}
	}
}

func (tracker *AllocationTracker) ComputeStats() []*StackStats {
	stats := make(map[uint32]*StackStats)

	for _, alloc := range tracker.ActiveObjects {
		if !tracker.HasStack(alloc.StackId) {
			slog.Warn("stack not found", "stackId", alloc.StackId)
			continue
		}

		if _, ok := stats[alloc.StackId]; !ok {
			ips := tracker.Stacks[alloc.StackId]

			probeSpec, ok := tracker.ProbeSpecs[alloc.ProbeId]

			objectSpec := probeSpec.objectSpec

			var err error

			if !ok {
				err = fmt.Errorf("stack %d not found in specs", alloc.StackId)
			}

			stats[alloc.StackId] = &StackStats{
				countActive: 1,
				stackId:     alloc.StackId,
				objectSpec:  objectSpec,
				pow2Hist:    make([]uint64, 16),
				ips:         ips,
				pid:         alloc.Pid,
				tgid:        alloc.Tgid,
				err:         err,
			}
		} else {
			stats[alloc.StackId].countActive += 1
		}

		stats[alloc.StackId].updateHist((tracker.LastTime - alloc.AllocTstamp) / NS_IN_SEC)
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

func (tracker *AllocationTracker) GetStackStats(stackId uint32) StackStats {
	if !tracker.HasStack(stackId) {
		return StackStats{
			err: fmt.Errorf("stack %d not found", stackId),
		}
	}

	var stats *StackStats

	for _, alloc := range tracker.ActiveObjects {
		if alloc.StackId != stackId {
			continue
		}

		if stats == nil {
			ips := tracker.Stacks[alloc.StackId]

			probeSpec, ok := tracker.ProbeSpecs[alloc.ProbeId]

			var err error

			if !ok {
				err = fmt.Errorf("stack %d not found in specs", stackId)
			}

			stats = &StackStats{
				countActive: 1,
				stackId:     alloc.StackId,
				pid:         alloc.Pid,
				objectSpec:  probeSpec.objectSpec,
				pow2Hist:    make([]uint64, 16),
				ips:         ips,
				err:         err,
			}
		} else {
			stats.countActive += 1
		}

		stats.updateHist((tracker.LastTime - alloc.AllocTstamp) / NS_IN_SEC)
	}

	return *stats
}

func (tracker *AllocationTracker) GetStacks() []*StackStats {
	return tracker.ComputeStats()
}

func (tracker *AllocationTracker) GetTraces() []*StatsBucket {
	return tracker.Stats.ToSlice()
}
