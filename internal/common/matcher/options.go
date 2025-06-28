package matcher

import (
	"context"
	"dissect/internal/model"

	"github.com/songzhibin97/gkit/cache/local_cache"
)

type MatcherOption struct {
	n          string
	filterFunc func(c *local_cache.Cache) bool
	queryFunc  func() []MatchConstraint
}

type DefaultMatcher struct{}

// Filter implements Matcher.
func (d *DefaultMatcher) Filter(c *local_cache.Cache) bool {
	return true
}

// Name implements Matcher.
func (d *DefaultMatcher) Name() string {
	return "default"
}

// Query implements Matcher.
func (d *DefaultMatcher) Query() []MatchConstraint {
	return []MatchConstraint{
		Vendor,
		Type,
		Name,
		Num,
		CpuType,
		FirmwareVersion,
	}
}

// Vulnerable implements Matcher.
func (d *DefaultMatcher) Vulnerable(ctx context.Context, record *local_cache.Cache, vuln *model.Vulnerability) (bool, error) {
	panic("unimplemented")
}

func NewMatcher() *MatcherOption {
	return &MatcherOption{}
}

func (*MatcherOption) Build() *DefaultMatcher {
	return &DefaultMatcher{}
}

func (m *MatcherOption) WithFilter(f func(c *local_cache.Cache) bool) *MatcherOption {
	m.filterFunc = f
	return m
}

func (m *MatcherOption) WithName(name string) *MatcherOption {
	m.n = name
	return m
}

func (m *MatcherOption) WithQuery(q func() []MatchConstraint) *MatcherOption {
	m.queryFunc = q
	return m
}
