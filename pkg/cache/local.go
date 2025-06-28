package cache

import (
	"time"

	"github.com/songzhibin97/gkit/cache/local_cache"
)

func NewCache(expire time.Duration) local_cache.Cache {
	return local_cache.NewCache(
		local_cache.SetDefaultExpire(expire),
		local_cache.SetCapture(nil),
	)
}
