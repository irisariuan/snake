// Package system wraps the router's command-line tools.
package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner executes external commands. Tests and dry runs substitute a recorder.
type Runner interface {
	Run(name string, args ...string) (string, error)
	RunInput(input, name string, args ...string) (string, error)
}

// Exec runs real commands with a timeout.
type Exec struct {
	Timeout time.Duration
}

func (e Exec) timeout() time.Duration {
	if e.Timeout == 0 {
		return 30 * time.Second
	}
	return e.Timeout
}

// Run executes name with args and returns combined output.
func (e Exec) Run(name string, args ...string) (string, error) {
	return e.RunInput("", name, args...)
}

// RunInput executes name feeding input on stdin.
func (e Exec) RunInput(input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		return s, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, s)
	}
	return s, nil
}

// Recorder records commands instead of running them (dry run / tests).
type Recorder struct {
	mu       sync.Mutex
	Commands []string
	// Responses maps a command prefix to canned output.
	Responses map[string]string
	// Fail maps a command prefix to a forced error.
	Fail map[string]bool
}

func (r *Recorder) Run(name string, args ...string) (string, error) {
	return r.RunInput("", name, args...)
}

func (r *Recorder) RunInput(input, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if input != "" {
		line += " <<EOF\n" + strings.TrimRight(input, "\n") + "\nEOF"
	}
	r.Commands = append(r.Commands, line)
	for p := range r.Fail {
		if strings.HasPrefix(line, p) {
			return "", fmt.Errorf("forced failure: %s", line)
		}
	}
	for p, out := range r.Responses {
		if strings.HasPrefix(line, p) {
			return out, nil
		}
	}
	return "", nil
}

// Joined returns all recorded commands joined by newlines.
func (r *Recorder) Joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.Commands, "\n")
}

// NVRAM reads Merlin nvram variables.
type NVRAM struct {
	R Runner
}

// Get returns the value of an nvram variable ("" on error).
func (n NVRAM) Get(key string) string {
	out, err := n.R.Run("nvram", "get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Exists reports whether an executable is available.
func Exists(path string) bool {
	if strings.Contains(path, "/") {
		st, err := os.Stat(path)
		return err == nil && !st.IsDir()
	}
	_, err := exec.LookPath(path)
	return err == nil
}

// WriteIfChanged writes data only when content differs (protects JFFS from wear).
func WriteIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	old, err := os.ReadFile(path)
	if err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}
