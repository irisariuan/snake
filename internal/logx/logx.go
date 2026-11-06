// Package logx is a tiny leveled logger that writes to syslog/stderr and keeps
// a ring buffer for the web UI.
package logx

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"sync"
	"time"
)

// Entry is one log line.
type Entry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

var (
	mu     sync.Mutex
	ring   = make([]Entry, 0, 500)
	sysw   *syslog.Writer
	out    io.Writer = os.Stderr
	debug  bool
	maxLen = 500
)

// Init connects to syslog (best effort) and sets the debug flag.
func Init(tag string, toSyslog, dbg bool) {
	mu.Lock()
	defer mu.Unlock()
	debug = dbg
	if toSyslog {
		if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag); err == nil {
			sysw = w
			out = io.Discard
		}
	}
}

func emit(level, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	mu.Lock()
	defer mu.Unlock()
	if len(ring) >= maxLen {
		copy(ring, ring[1:])
		ring = ring[:maxLen-1]
	}
	ring = append(ring, Entry{Time: time.Now(), Level: level, Msg: msg})
	fmt.Fprintf(out, "%s [%s] %s\n", time.Now().Format("15:04:05"), level, msg)
	if sysw != nil {
		switch level {
		case "ERROR":
			_ = sysw.Err(msg)
		case "WARN":
			_ = sysw.Warning(msg)
		case "DEBUG":
			_ = sysw.Debug(msg)
		default:
			_ = sysw.Info(msg)
		}
	}
}

func Debugf(format string, a ...any) {
	if debug {
		emit("DEBUG", format, a...)
	}
}
func Infof(format string, a ...any)  { emit("INFO", format, a...) }
func Warnf(format string, a ...any)  { emit("WARN", format, a...) }
func Errorf(format string, a ...any) { emit("ERROR", format, a...) }

// Recent returns a copy of the ring buffer.
func Recent() []Entry {
	mu.Lock()
	defer mu.Unlock()
	return append([]Entry(nil), ring...)
}
