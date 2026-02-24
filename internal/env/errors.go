package env

import "errors"

var (
	ErrEmptyPath  = errors.New("environment path is empty")
	ErrUnsafePath = errors.New("environment path is unsafe")
)
