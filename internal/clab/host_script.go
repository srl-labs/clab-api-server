// internal/clab/host_script.go
package clab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	// hostScriptStopGrace is how long a stopped script may clean up before everything
	// it started is killed.
	hostScriptStopGrace = 5 * time.Second
	// hostScriptDrainQuiet ends reading after the script exits, once its pipes stay quiet
	// this long. Something it left running can hold them open forever.
	hostScriptDrainQuiet = 500 * time.Millisecond
	// hostScriptDrainLimit ends it in any case, when that something keeps writing.
	hostScriptDrainLimit = 5 * time.Second
	hostScriptChunkBytes = 32 * 1024
)

// HostScriptOptions says what to run and as whom.
type HostScriptOptions struct {
	// Args are bash's arguments: the script file, or -c and the script.
	Args []string
	Dir  string
	Env  []string
	// Credential is the account the script runs as; nil keeps this process's account,
	// which only callers that checked it is the right one may ask for.
	Credential *syscall.Credential
}

// HostScriptOutput is one piece of a script's output.
type HostScriptOutput struct {
	Stream string
	Text   string
}

// HostScriptExit is how a script ended.
type HostScriptExit struct {
	// ExitCode is nil when a signal stopped the script.
	ExitCode *int
	TimedOut bool
	// Cancelled means the context ended for another reason than its deadline: the client left.
	Cancelled bool
	Duration  time.Duration
}

// HostScriptRun is a started script.
type HostScriptRun struct {
	// Output closes after the script exits and its output is read. Not reading it makes
	// the script wait, so a slow client cannot fill this server's memory.
	Output <-chan HostScriptOutput
	// Done delivers how the script ended, once, after Output closed.
	Done <-chan HostScriptExit
}

// StartHostScript starts bash in a session of its own, so that stopping it reaches
// what it started. Ending ctx stops it: SIGTERM to the whole group, then SIGKILL. What
// it leaves running when it exits by itself stays, without its output pipes.
func StartHostScript(ctx context.Context, opts HostScriptOptions) (*HostScriptRun, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		return nil, err
	}

	cmd := exec.Command("bash", opts.Args...)
	cmd.Dir = opts.Dir
	cmd.Env = opts.Env
	cmd.Stdout = stdoutWrite
	cmd.Stderr = stderrWrite
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: opts.Credential}

	started := time.Now()
	startErr := cmd.Start()
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	if startErr != nil {
		_ = stdoutRead.Close()
		_ = stderrRead.Close()
		return nil, startErr
	}

	output := make(chan HostScriptOutput, 16)
	done := make(chan HostScriptExit, 1)
	processExited := make(chan struct{})
	var exited atomic.Bool

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-processExited:
			return
		}
		close(stopped)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		// Children can outlive or ignore the signal, so this goes on after bash has exited.
		time.Sleep(hostScriptStopGrace)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()

	readers := make(chan struct{}, 2)
	readPipe := func(stream string, pipe *os.File) {
		defer func() {
			_ = pipe.Close()
			readers <- struct{}{}
		}()
		readHostScriptPipe(ctx, stream, pipe, output, &exited)
	}
	go readPipe("stdout", stdoutRead)
	go readPipe("stderr", stderrRead)

	go func() {
		// The exit code below tells everything a caller can use.
		_ = cmd.Wait()
		exited.Store(true)
		close(processExited)
		// Wake readers that wait on a pipe something else still holds open.
		deadline := time.Now().Add(hostScriptDrainQuiet)
		_ = stdoutRead.SetReadDeadline(deadline)
		_ = stderrRead.SetReadDeadline(deadline)
		<-readers
		<-readers
		close(output)

		result := HostScriptExit{Duration: time.Since(started)}
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() >= 0 {
			code := cmd.ProcessState.ExitCode()
			result.ExitCode = &code
		}
		select {
		case <-stopped:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				result.TimedOut = true
			} else {
				result.Cancelled = true
			}
		default:
		}
		done <- result
	}()

	return &HostScriptRun{Output: output, Done: done}, nil
}

// readHostScriptPipe passes output on until the pipe closes, the client is gone, or the
// script has exited and what it left behind stays quiet or the drain limit passes.
func readHostScriptPipe(
	ctx context.Context,
	stream string,
	pipe *os.File,
	output chan<- HostScriptOutput,
	exited *atomic.Bool,
) {
	buffer := make([]byte, hostScriptChunkBytes)
	carry := 0 // Bytes of a character split across two reads, kept at the buffer's start.
	var drainUntil time.Time
	for {
		if exited.Load() {
			if drainUntil.IsZero() {
				drainUntil = time.Now().Add(hostScriptDrainLimit)
			}
			if time.Now().After(drainUntil) {
				return
			}
			_ = pipe.SetReadDeadline(time.Now().Add(hostScriptDrainQuiet))
		}
		count, err := pipe.Read(buffer[carry:])
		if count > 0 {
			available := carry + count
			complete := completeUTF8Prefix(buffer[:available])
			if complete > 0 && !sendHostScriptOutput(ctx, output, stream, string(buffer[:complete])) {
				return
			}
			carry = copy(buffer, buffer[complete:available])
		}
		if err != nil {
			if carry > 0 {
				sendHostScriptOutput(ctx, output, stream, string(buffer[:carry]))
			}
			return
		}
	}
}

// sendHostScriptOutput waits for the reader. A client that left stops reading, and its
// context ends then, so this does not wait forever.
func sendHostScriptOutput(ctx context.Context, output chan<- HostScriptOutput, stream, text string) bool {
	select {
	case output <- HostScriptOutput{Stream: stream, Text: text}:
		return true
	case <-ctx.Done():
		return false
	}
}

// completeUTF8Prefix returns how much of data ends on a character boundary. Invalid
// bytes count as complete: they will not become valid by waiting.
func completeUTF8Prefix(data []byte) int {
	for back := 1; back <= utf8.UTFMax-1 && back <= len(data); back++ {
		position := len(data) - back
		if !utf8.RuneStart(data[position]) {
			continue
		}
		if !utf8.FullRune(data[position:]) {
			return position
		}
		break
	}
	return len(data)
}
