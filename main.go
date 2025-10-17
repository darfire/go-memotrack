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
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ebpf ebpf.c

func ParseObjectSpec(s string, idx int) (ObjectSpec, error) {
	var spec ObjectSpec

	tokens := strings.Split(s, "=")

	if len(tokens) != 2 {
		return ObjectSpec{}, fmt.Errorf("invalid spec format: %s", s)
	}

	spec.Name = tokens[0]
	spec.Type = uint16(idx)

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
	var pidsString string
	var executable string
	var specStrings []string
	var logLevel string
	var interactive bool
	var outputDir string
	var configPath string
	var config Config

	flag.IntSliceVar(&pids, "pid", []int{}, "pid of a process to track. Can be specified multiple times.")
	flag.StringVar(&pidsString, "pids", "", "a space-separate list of pids(meant to be used with pidof)")
	flag.StringVar(&executable, "executable", "", "the executable to track")
	flag.StringSliceVar(&specStrings, "object", []string{}, "An allocator spec of the form name=alloc1,alloc2|free1,free2,free3")
	flag.StringVar(&logLevel, "log-level", "info", "log level")
	flag.BoolVar(&interactive, "interactive", false, "run in interactive mode")
	flag.StringVar(&outputDir, "output-dir", "", "directory to write reports in")
	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.Parse()

	if pidsString != "" {
		for _, s := range strings.Fields(pidsString) {

			pid, err := strconv.ParseInt(s, 10, 32)

			if err != nil {
				log.Fatalf("error parsing pid: %s", err)
			}

			pids = append(pids, int(pid))
		}
	}

	if configPath != "" {
		var err error
		config, err = ParseConfig(configPath)
		if err != nil {
			log.Fatalf("error parsing config: %s", err)
		}
	}

	if executable != "" {
		config.Executable = executable
	}

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: parseLogLevel(logLevel),
		}),
	)

	slog.SetDefault(logger)

	if len(pids) == 0 {
		log.Fatalf("no pids specified")
	}

	for i, s := range specStrings {
		spec, err := ParseObjectSpec(s, i+1)

		if err != nil {
			log.Fatalf("error parsing spec: %s", err)
		}

		config.Objects[spec.Name] = spec
	}

	if len(config.Objects) > MAX_OBJECT_TYPES {
		log.Fatalf("too many object types")
	}

	objects := make([]ObjectSpec, len(config.Objects))

	currentType := uint16(1)

	for _, s := range config.Objects {
		if len(s.Allocators) == 0 || len(s.Deallocators) == 0 {
			log.Fatalf("Object %s needs at least one allocator and one deallocator", s.Name)
		}

		s.Type = currentType

		currentType += 1

		objects = append(objects, s)
	}

	if len(objects) == 0 {
		log.Fatalf("no objects specified")
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

	log.Printf("Opening executable %s...", config.Executable)

	ex, err := link.OpenExecutable(config.Executable)

	if err != nil {
		log.Fatalf("opening executable: %v", err)
	}

	slog.Debug("attached to executable.", "path", config.Executable)
	currentProbeId := uint16(0)
	options := link.UprobeOptions{PID: 0, Cookie: 0}

	probeSpecs := make([]ProbeSpec, 0)

	for _, s := range objects {
		for _, a := range s.Allocators {
			currentProbeId += 1
			options.Cookie = uint64(currentProbeId)
			for _, pid := range pids {
				options.PID = pid

				up, err := ex.Uretprobe(a, objs.UretprobeMalloc, &options)
				if err != nil {
					log.Fatalf("opening allocator probe: %v", err)
				}

				probeSpecs = append(probeSpecs, ProbeSpec{
					probeId:    currentProbeId,
					symbolName: a,
					probeType:  AllocatorProbe,
					objectSpec: &s,
				})

				slog.Debug("attached to allocator", "symbol", a, "pid", pid)

				defer up.Close()
			}
		}

		for _, d := range s.Deallocators {
			currentProbeId += 1
			options.Cookie = uint64(currentProbeId)
			for _, pid := range pids {
				options.PID = pid

				up, err := ex.Uprobe(d, objs.UprobeFree, &options)
				if err != nil {
					log.Fatalf("opening deallocator probe: %v", err)
				}

				probeSpecs = append(probeSpecs, ProbeSpec{
					probeId:    currentProbeId,
					symbolName: d,
					probeType:  DeallocatorProbe,
					objectSpec: &s,
				})

				slog.Debug("attached to deallocator", "symbol", d, "pid", pid)

				defer up.Close()
			}
		}
	}

	for _, reference := range config.References {
		currentProbeId += 1
		options.Cookie = uint64(currentProbeId)
		for _, pid := range pids {
			options.PID = pid

			up, err := ex.Uprobe(reference, objs.UprobeReference, &options)
			if err != nil {
				log.Fatalf("opening reference signal probe: %v", err)
			}

			probeSpecs = append(probeSpecs, ProbeSpec{
				probeId:    currentProbeId,
				symbolName: reference,
				probeType:  ReferenceProbe,
			})

			slog.Debug("attached to reference signal", "symbol", reference, "pid", pid)

			defer up.Close()
		}
	}

	eventReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer eventReader.Close()

	go func() {
		<-stopper
		err1 := eventReader.Close()
		if err1 != nil {
			log.Fatalf("closing events ringbuf reader: %s", err)
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
		ObjectSpecs:     objects,
		ProbeSpecs:      probeSpecs,
		SampleIntervalS: uint64(config.SampleSeconds),
		MaxStatsBuckets: uint64(config.MaxStatsBuckets),
	}

	tracker := NewAllocationTracker(trackerOptions)

	requestChan := make(chan TrackerRequest, 128)

	defer close(requestChan)

	go tracker.Run(requestChan, stopper)

	executableFname := path.Base(config.Executable)

	if outputDir == "" {
		outputDir = fmt.Sprintf("reports-%s-%d", executableFname, time.Now().Unix())
	}

	formatterOptions := FormatterOptions{
		pids:      pids,
		reportDir: outputDir,
	}

	formatter := NewFormatter(formatterOptions)

	defer func() {
		formatter.writeStacks(tracker.GetStacks())
		formatter.writeTraces(tracker.GetTraces())
	}()

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
		record, err := eventReader.Read()
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
}
