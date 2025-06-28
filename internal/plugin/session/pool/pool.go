package pool

import (
	"fmt"
	"runtime"

	"github.com/panjf2000/ants/v2"
)

// MustPool 注册协程池  size:数量 sizePool:容量
func MustPool(quantity, capacity int) *ants.MultiPool {
	if quantity == 0 || quantity == -1 {
		quantity = runtime.GOMAXPROCS(0) // 线程数
	}
	if capacity == 0 || capacity == -1 {
		capacity = 500 // 1k
	}

	mp, _ := ants.NewMultiPool(quantity, capacity, ants.LeastTasks, ants.WithOptions(ants.Options{
		ExpiryDuration:   0,
		PreAlloc:         false,
		MaxBlockingTasks: 10000, // 允许溢出且阻塞
		Nonblocking:      false,
		PanicHandler: func(i interface{}) {
			fmt.Println("a task in the current pool is abnormal. Procedure", i)
		},
		DisablePurge: false,
	}))
	return mp
}
