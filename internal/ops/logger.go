package ops

import (
	"fmt"
	"time"
)

type Logger struct {
	Level string
}

func NewLogger(level string) Logger {
	if level == "" {
		level = "info"
	}
	return Logger{Level: level}
}

func (l Logger) Info(msg string) {
	if l.Level == "debug" || l.Level == "info" {
		fmt.Printf("%s [INFO] %s\n", time.Now().UTC().Format(time.RFC3339), msg)
	}
}

func (l Logger) Debug(msg string) {
	if l.Level == "debug" {
		fmt.Printf("%s [DEBUG] %s\n", time.Now().UTC().Format(time.RFC3339), msg)
	}
}

func (l Logger) Warn(msg string) {
	fmt.Printf("%s [WARN] %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}
