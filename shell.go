package main

import (
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
	live_stack "github.com/darfire/go-live-stack"
)

type Shell struct {
	ctxs map[int]*live_stack.ProcessContext
}

type ShellOptions struct {
	Pids []int
}

func NewShell(options ShellOptions) (Shell, error) {
	ctxs := make(map[int]*live_stack.ProcessContext)
	for _, pid := range options.Pids {
		ctx, err := live_stack.NewProcessContext(pid)

		if err != nil {
			return Shell{}, err
		}

		ctxs[pid] = &ctx
	}

	return Shell{
		ctxs,
	}, nil
}

func (shell *Shell) Run(requestChan chan TrackerRequest, stopper chan interface{}) {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[31m»\033[0m ",
		HistoryFile:     "/tmp/readline.tmp",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		HistorySearchFold: true,
		// FuncFilterInputRune: filterInput,
	})

	if err != nil {
		panic(err)
	}
	rl.CaptureExitSignal()

	log.SetOutput(rl.Stderr())

	lineChan := make(chan string)

	go func() {
		defer close(lineChan)

	outerLoop:
		for {
			line, err := rl.Readline()

			if err == nil {
				lineChan <- line
			} else {
				if err == readline.ErrInterrupt {
					if len(line) == 0 {
						close(stopper)
						break outerLoop
					} else {
						continue
					}
				} else if err == io.EOF {
					close(stopper)
					break outerLoop
				} else {
					log.Printf("error reading line: %s", err)
				}
			}
		}
	}()

	go func() {
		for range stopper {
			rl.Close()
		}
	}()

outerLoop:
	for line := range lineChan {
		command, err := shell.handleLine(line)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if command.requestType == CmdExit {
			close(stopper)
			break outerLoop
		}
		requestChan <- command
		if command.responseChan != nil {
			select {
			case response := <-command.responseChan:
				fmt.Println(shell.Format(response))
			case <-stopper:
				break outerLoop
			}
		}
	}
}

func (shell *Shell) handleLine(line string) (TrackerRequest, error) {
	tokens := strings.Fields(line)

	if len(tokens) == 0 {
		return NewTrackerRequest(CmdNop, nil, nil), nil
	}

	switch tokens[0] {
	case "exit":
		return NewTrackerRequest(CmdExit, nil, nil), nil
	case "stats":
		return NewTrackerRequest(CmdGetAllStats, nil, make(chan TrackerResponse, 1)), nil
	case "show":
		parsedStackId, err := strconv.ParseUint(tokens[1], 10, 32)
		if err != nil {
			fmt.Printf("error parsing stack id: %s\n", err)
			return NewTrackerRequest(CmdNop, nil, nil), nil
		}
		stackId := uint32(parsedStackId)
		return NewTrackerRequest(CmdGetSingleStats, stackId, make(chan TrackerResponse, 1)), nil
	case "trends":
		var stackId uint32

		stackId = 0

		if len(tokens) > 1 {
			var err error
			parsedStackId, err := strconv.ParseUint(tokens[1], 10, 32)
			if err != nil {
				fmt.Printf("error parsing stack id: %s\n", err)
				return NewTrackerRequest(CmdNop, nil, nil), nil
			}

			stackId = uint32(parsedStackId)
		}

		return NewTrackerRequest(CmdGetTrends, stackId, make(chan TrackerResponse, 1)), nil
	default:
		fmt.Printf("unknown command: '%s'\n", line)
		return NewTrackerRequest(CmdNop, nil, nil), nil
	}
}

func (shell *Shell) formatAllStats(stats AllStatsPayload) string {
	var sb strings.Builder

	for idx, s := range stats.stacks {
		history := ExtractSingleHistory(stats.history, s.stackId)
		sb.WriteString(fmt.Sprintf("%d: %s\n", idx, shell.formatStack(s, history)))
	}

	return sb.String()
}

func (shell *Shell) formatStack(stats *StackStats, history []SingleStackHistory) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("stackId: %d, name:%s, #objects: %d\n", stats.stackId, stats.objectSpec.Name, stats.countActive))

	sb.WriteString(fmt.Sprintf("ips: %v\n", stats.ips))

	sb.WriteString("pow2Hist: ")

	for k, v := range stats.pow2Hist {
		sb.WriteString(fmt.Sprintf("%d:%d, ", 1<<k, v))
	}

	ctx, ok := shell.ctxs[stats.pid]

	if !ok {
		log.Printf("ctx for pid %d not found", stats.pid)
		sb.WriteString("\n")
		return sb.String()
	}

	frames := ctx.GetStackTrace(stats.ips)

	sb.WriteString("frames:\n")

	for idx, f := range frames {
		sb.WriteString(fmt.Sprintf("%s\n", f.Describe(idx)))
	}

	sb.WriteString("history:\n")

	for _, h := range history {
		sb.WriteString(fmt.Sprintf("%d	", h.Count))
	}

	sb.WriteString("\n")

	return sb.String()
}

func (shell *Shell) Format(response TrackerResponse) string {
	if response.err != nil {
		return fmt.Sprintf("error: %s", response.err)
	}

	switch response.requestType {
	case CmdGetAllStats:
		return shell.formatAllStats(response.payload.(AllStatsPayload))
	case CmdGetSingleStats:
		payload := response.payload.(SingleStatsPayload)
		return shell.formatStack(payload.stack, payload.history)
	default:
		return fmt.Sprintf("unknown response type: %d", response.requestType)
	}
}
