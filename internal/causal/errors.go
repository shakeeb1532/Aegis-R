package causal

import "errors"

var (
	ErrInvalidModel      = errors.New("invalid causal model")
	ErrUnknownNode       = errors.New("unknown causal node")
	ErrCycleDetected     = errors.New("causal model cycle detected")
	ErrMissingEquation   = errors.New("missing causal equation")
	ErrModelNotReady     = errors.New("causal model not initialized")
	ErrOutcomeNotPresent = errors.New("causal outcome not present")
)
