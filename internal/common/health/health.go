package health

import (
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
)

// 心跳共享内存结构
type Heartbeat struct {
	LastPing    int64 `json:"last_ping"` // 纳秒时间戳
	LastPong    int64 `json:"last_pong"`
	ParentAlive int32 `json:"parent_alive"`
	ChildAlive  int32 `json:"child_alive"`
}

// 父进程心跳发送
func StartHeartbeat(hb *Heartbeat) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		atomic.StoreInt64(&hb.LastPing, time.Now().UnixNano())
		atomic.StoreInt32(&hb.ParentAlive, 1)
	}
}

// 子进程心跳响应
func StartHeartResponse(hb *Heartbeat) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt32(&hb.ParentAlive) == 1 {
			atomic.StoreInt64(&hb.LastPong, time.Now().UnixNano())
			atomic.StoreInt32(&hb.ChildAlive, 1)
		}
	}
}

// 健康检查协程
func healthMonitor(hb *Heartbeat, cmd *exec.Cmd) {
	checkTicker := time.NewTicker(2 * time.Second)
	defer checkTicker.Stop()

	for range checkTicker.C {
		// 检查进程状态
		if processExited(cmd) {
			//restartChild(cmd)
			continue
		}

		// 检查双向心跳
		now := time.Now().UnixNano()
		if now-atomic.LoadInt64(&hb.LastPong) > 3e9 { // 3秒超时
			//handleUnhealthyChild(cmd)
		}
	}
}

func processExited(cmd *exec.Cmd) bool {
	process, _ := os.FindProcess(cmd.Process.Pid)
	err := process.Signal(syscall.Signal(0))
	return err != nil
}
