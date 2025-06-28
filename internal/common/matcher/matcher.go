package matcher

import (
	"context"
	"dissect/internal/model"

	"github.com/songzhibin97/gkit/cache/local_cache"
)

var DefaultMatchers = MatcherManager{
	Matchers: []Matcher{
		NewMatcher().Build(),
	},
}

// for example if sql implementation encounters a Name constraint
// it should create a query similar to "SELECT * FROM public_vuln WHERE name = ? AND version = ?"
type MatchConstraint int

//go:generate go run golang.org/x/tools/cmd/stringer -type MatchConstraint

const (
	_ MatchConstraint = iota
	// Vendor is the vendor name of the package
	Vendor
	Type
	Name
	Num
	CpuType
	FirmwareVersion
)

// MatcherManager is used to manage the matchers
type MatcherManager struct {
	Matchers []Matcher
}

type Matcher interface {
	Name() string                     // Name is used to get the name of the matcher
	Filter(c *local_cache.Cache) bool // Filter is used to filter the data
	Query() []MatchConstraint         // Match is used to match the data
	Vulnerable(ctx context.Context, record *local_cache.Cache, vuln *model.Vulnerability) (bool, error)
}
