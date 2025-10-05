//go:build amd64 && linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ebpf ebpf.c

type ObjectSpec struct {
	Type         uint8
	Name         string
	Allocators   []string
	Deallocators []string
}

func ParseObjectSpec(s string, idx int) (ObjectSpec, error) {
	var spec ObjectSpec

	tokens := strings.Split(s, "=")

	if len(tokens) != 2 {
		return ObjectSpec{}, fmt.Errorf("invalid spec format: %s", s)
	}

	spec.Name = tokens[0]
	spec.Type = uint8(idx)

	allocAndDealloc := strings.Split(tokens[1], "|")

	if len(allocAndDealloc) != 2 {
		return ObjectSpec{}, fmt.Errorf("invalid spec format: %s", s)
	}

	spec.Allocators = strings.Split(allocAndDealloc[0], ",")
	spec.Deallocators = strings.Split(allocAndDealloc[1], ",")

	return spec, nil
}

const MAX_OBJECT_TYPES = 16

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func main() {
	var pids []int
	var executable string
	var specStrings []string
	var logLevel string
	var interactive bool
	var output string

	flag.IntSliceVar(&pids, "pid", []int{}, "the pid to track")
	flag.StringVar(&executable, "executable", "", "the executable to track")
	flag.StringSliceVar(&specStrings, "object", []string{}, "An allocator spec of the form name=alloc1,alloc2|free1,free2,free3")
	flag.StringVar(&logLevel, "log-level", "info", "log level")
	flag.BoolVar(&interactive, "interactive", false, "run in interactive mode")
	flag.StringVar(&output, "output", "-", "file to write report to")
	flag.Parse()

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: parseLogLevel(logLevel),
		}),
	)

	slog.SetDefault(logger)

	if len(specStrings) > MAX_OBJECT_TYPES {
		log.Fatalf("too many object types, max is %d", MAX_OBJECT_TYPES)
	}

	if len(pids) == 0 {
		log.Fatalf("no pids specified")
	}

	var specs []ObjectSpec

	for i, s := range specStrings {
		spec, err := ParseObjectSpec(s, i+1)

		if err != nil {
			log.Fatalf("error parsing spec: %s", err)
		}

		specs = append(specs, spec)
	}

	for _, s := range specs {
		if len(s.Allocators) == 0 || len(s.Deallocators) == 0 {
			log.Fatalf("Object %s needs at least one allocator and one deallocator", s.Name)
		}
	}

	stopper := make(chan interface{}, 1)

	if !interactive {
		signalStopper := make(chan os.Signal, 1)
		signal.Notify(signalStopper, os.Interrupt, syscall.SIGTERM)

		defer close(signalStopper)

		go func() {
			// forward stopped by signal to generic stopper
			<-signalStopper
			log.Println("Received signal, exiting..")
			close(stopper)
		}()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := ebpfObjects{}

	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(executable)

	if err != nil {
		log.Fatalf("opening executable: %v", err)
	}

	slog.Debug("attached to executable.")

	for _, pid := range pids {
		for _, s := range specs {
			options := link.UprobeOptions{PID: pid, Cookie: uint64(s.Type)}

			for _, a := range s.Allocators {
				up, err := ex.Uretprobe(a, objs.UretprobeMalloc, &options)
				if err != nil {
					log.Fatalf("opening allocator probe: %v", err)
				}

				slog.Debug("attached to allocator", "symbol", a, "pid", pid)

				defer up.Close()
			}

			for _, d := range s.Deallocators {
				up, err := ex.Uprobe(d, objs.UprobeFree, &options)
				if err != nil {
					log.Fatalf("opening deallocator probe: %v", err)
				}

				slog.Debug("attached to deallocator", "symbol", d, "pid", pid)

				defer up.Close()
			}
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	trackerOptions := TrackerOptions{
		LookupStack: func(stack_id uint32) []uint64 {
			ips := make([]uint64, 8)

			err := objs.Stacks.Lookup(stack_id, &ips)

			if err != nil {
				log.Printf("error looking up stack: %s", err)
				return nil
			} else {
				return ips
			}
		},
		Specs:             specs,
		MaxHistoryBuckets: 128,
		HistoryIntervalS:  60,
	}

	tracker := NewAllocationTracker(trackerOptions)

	requestChan := make(chan TrackerRequest, 128)

	defer close(requestChan)

	go tracker.Run(requestChan, stopper)

	formatter := NewFormatter(pids)

	if interactive {
		shellOptions := ShellOptions{
			formatter: &formatter,
		}
		shell, err := NewShell(shellOptions)

		if err != nil {
			log.Fatalf("error creating shell: %s", err)
		}

		go shell.Run(requestChan, stopper)
	}

readLoop:
	for {
		record, err := rd.Read()
		// slog.Debug("received event", "record", record)

		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break readLoop
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		event := ebpfEventT{}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		// slog.Debug("sending to tracker", "event", event)

		requestChan <- NewTrackerRequest(CmdAddEvent, event, nil)
	}

	var outputFile *os.File

	if output == "-" {
		outputFile = os.Stdout
	} else {
		var err error
		outputFile, err = os.Create(output)
		if err != nil {
			log.Fatalf("error creating output file: %s", err)
		}
		defer outputFile.Close()
	}

	outputFile.WriteString(formatter.formatAllStats(tracker.GetAllStats()))
}
