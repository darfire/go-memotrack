package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	live_stack "github.com/darfire/go-live-stack"
)

type Formatter struct {
	pids      []int
	ctxs      map[int]*live_stack.ProcessContext
	reportDir string
}

type FormatterOptions struct {
	pids      []int
	reportDir string
}

func NewFormatter(options FormatterOptions) Formatter {
	ctxs := make(map[int]*live_stack.ProcessContext)
	for _, pid := range options.pids {
		ctx, err := live_stack.NewProcessContext(int(pid))

		if err != nil {
			panic(err)
		}

		ctxs[int(pid)] = &ctx
	}

	return Formatter{
		pids:      options.pids,
		ctxs:      ctxs,
		reportDir: options.reportDir,
	}
}

func (formatter *Formatter) formatAllStats(stats []*StackStats) string {
	var sb strings.Builder

	log.Printf("Formatting %d stacks", len(stats))

	for idx, s := range stats {
		sb.WriteString(fmt.Sprintf("%d: %s\n", idx, formatter.formatStack(s)))
	}

	return sb.String()
}

func (formatter *Formatter) formatStack(stats *StackStats) string {
	var sb strings.Builder

	sb.WriteString(
		fmt.Sprintf("stackId: %d, name:%s, #objects: %d, pid: %d\n",
			stats.stackId, stats.objectSpec.Name, stats.countActive, stats.pid))

	ipsStrings := make([]string, len(stats.ips))

	for idx, ip := range stats.ips {
		ipsStrings[idx] = fmt.Sprintf("0x%x", ip)
	}

	sb.WriteString(fmt.Sprintf("ips: %s\n", strings.Join(ipsStrings, ", ")))

	sb.WriteString("pow2Hist: ")

	for k, v := range stats.pow2Hist {
		sb.WriteString(fmt.Sprintf("%d:%d, ", 1<<k, v))
	}

	ctx, ok := formatter.ctxs[int(stats.pid)]

	if !ok {
		log.Printf("ctx for pid %d not found", stats.pid)
		sb.WriteString("\n")
		return sb.String()
	}

	frames := ctx.GetStackTrace(stats.ips)

	sb.WriteString("frames:\n")

	for idx, f := range frames {
		if f.IsNull() {
			break
		}
		sb.WriteString(fmt.Sprintf("%s\n", f.Describe(idx)))
	}

	sb.WriteString("\n")

	return sb.String()
}

func (formatter *Formatter) ensureDir() {
	if formatter.reportDir == "" {
		return
	}
	if _, err := os.Stat(formatter.reportDir); os.IsNotExist(err) {
		err := os.MkdirAll(formatter.reportDir, 0755)
		if err != nil {
			log.Printf("error creating report dir: %s", err)
		}
	}
}

func (formatter *Formatter) writeTraces(trace []*StatsBucket) {
	formatter.ensureDir()

	fname := fmt.Sprintf("trace-%d.csv", time.Now().Unix())

	path := path.Join(formatter.reportDir, fname)

	keys := make(map[string]bool)

	for _, b := range trace {
		log.Printf("Looking at trace bucket %v", b)

		for k := range b.Counts {
			keys[k] = true
		}
	}

	keysSlice := make([]string, 0, len(keys)+1)

	keysSlice = append(keysSlice, "timestamp")

	for k := range keys {
		keysSlice = append(keysSlice, k)
	}

	// keep timestmap first
	slices.Sort(keysSlice[1:])

	f, err := os.Create(path)

	if err != nil {
		log.Printf("error creating trace report: %s", err)
		return
	}

	defer f.Close()

	writer := csv.NewWriter(f)

	defer writer.Flush()

	writer.Write(keysSlice)

	for _, b := range trace {
		row := make([]string, len(keysSlice))
		row[0] = fmt.Sprintf("%d", b.TimeStamp)

		for i, k := range keysSlice[1:] {
			v, ok := b.Counts[k]

			if !ok {
				v = 0
			}

			row[i+1] = fmt.Sprintf("%d", v)
		}

		writer.Write(row)
	}
}

func (formatter *Formatter) writeStacks(stacks []*StackStats) {
	formatter.ensureDir()

	fname := "stacks.txt"

	path := path.Join(formatter.reportDir, fname)

	f, err := os.Create(path)

	if err != nil {
		log.Printf("error creating stacks report: %s", err)
		return
	}

	defer f.Close()

	slices.SortFunc(stacks, func(a, b *StackStats) int {
		return int(b.countActive) - int(a.countActive)
	})

	for _, s := range stacks {
		f.WriteString(formatter.formatStack(s))
	}
}
