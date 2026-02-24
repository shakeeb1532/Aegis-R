package logic

import "errors"

var (
	ErrInvalidRuleCatalog = errors.New("invalid rule catalog")
	ErrInvalidRulePath    = errors.New("invalid rule path")
)
