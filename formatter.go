package main

import (
	"fmt"
	"log"
	"strings"

	live_stack "github.com/darfire/go-live-stack"
)

type Formatter struct {
	pids []int
	ctxs map[int]*live_stack.ProcessContext
}

func NewFormatter(pids []int) Formatter {
	ctxs := make(map[int]*live_stack.ProcessContext)
	for _, pid := range pids {
		ctx, err := live_stack.NewProcessContext(int(pid))

		if err != nil {
			panic(err)
		}

		ctxs[int(pid)] = &ctx
	}

	return Formatter{
		pids,
		ctxs,
	}
}

func (formatter *Formatter) formatAllStats(stats AllStatsPayload) string {
	var sb strings.Builder

	log.Printf("Formatting %d stacks", len(stats.stacks))

	for idx, s := range stats.stacks {
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
