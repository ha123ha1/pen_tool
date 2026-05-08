package logger

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

type Logger struct {
	out   io.Writer
	level Level
	mu    sync.Mutex
}

func New(out io.Writer, level Level) *Logger {
	return &Logger{out: out, level: level}
}

func (l *Logger) Debug(format string, args ...any) { l.log(DebugLevel, "DEBUG", format, args...) }
func (l *Logger) Info(format string, args ...any)  { l.log(InfoLevel, "INFO", format, args...) }
func (l *Logger) Warn(format string, args ...any)  { l.log(WarnLevel, "WARN", format, args...) }
func (l *Logger) Error(format string, args ...any) { l.log(ErrorLevel, "ERROR", format, args...) }

func (l *Logger) log(level Level, label, format string, args ...any) {
	if l == nil || level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s [%s] %s\n", time.Now().Format(time.RFC3339), label, fmt.Sprintf(format, args...))
}
