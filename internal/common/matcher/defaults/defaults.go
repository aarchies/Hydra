package defaults

import (
	"context"
	"dissect/internal/common/matcher"

	"sync"
	"time"
)

var (
	once   sync.Once
	regerr error
)

func init() {
	ctx, done := context.WithTimeout(context.Background(), 1*time.Minute)
	defer done()
	once.Do(func() { regerr = inner(ctx) })
}

// Error reports if an error was encountered when initializing the default
// matchers.
func Error() error {
	return regerr
}

func inner(ctx context.Context) error {

	for _, m := range matcher.DefaultMatchers.Matchers {
		_ = m
	}

	return nil
}
