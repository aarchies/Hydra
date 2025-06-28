//go:build linux
// +build linux

package main

import (
	"dissect/internal/common/resolver"
	"dissect/internal/core/system"
	"dissect/internal/core/system/ipc"
	"dissect/internal/core/system/sem"
	"dissect/internal/core/system/shm"
	"dissect/internal/model/pb"

	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type c struct {
	id     uint64
	buffer *pb.ConsumerData
}

var (
	sigCh    = make(chan os.Signal, 1)
	ch       = make(chan c, 1024)
	req_SHM  = flag.String("mem", "", "ths child process maping file name")
	resp_SHM = flag.String("res_mem", "", "ths child process result buffer maping file name")
)

func init() {
	flag.Parse()
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("starting worker process Arguments: [%s] [%s] \n", *req_SHM, *resp_SHM)
	os.Stdout.Sync()
}

func main() {
	defer resolver.Exit()
	defer println("worker all stoping...")

	// open req shark mem
	fd, err := shm.Open(*req_SHM, unix.O_RDWR, 0)
	if err != nil {
		panic(fmt.Sprintf("req shm open error! %s", err))
	}

	addr, err := unix.Mmap(fd, 0, system.MEM_SIZE, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		panic(fmt.Sprintf("req mmap open error! %s", err))
	}
	defer unix.Munmap(addr)

	header, buffers := system.GetShmPointers(uintptr(unsafe.Pointer(&addr[0])))
	futex := (*sem.Semaphore)(unsafe.Pointer(&header.Futex))
	defer futex.Destroy()

	//init resp ringBuffer
	rfd, err := shm.Open(*resp_SHM, unix.O_RDWR, 0)
	if err != nil {
		panic(fmt.Sprintf("resp shm open error! %s", err))
	}

	raddr, err := unix.Mmap(rfd, 0, system.MEM_SIZE, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		panic(fmt.Sprintf("resp mmap open error! %s", err))
	}
	defer unix.Munmap(raddr)

	go callBack(raddr)

	for {

		futex.Wait()

		r := atomic.LoadUint64(&header.ReadIdx)
		w := atomic.LoadUint64(&header.WriteIdx)

		if r >= w {
			ipc.SchedYield()
			continue
		}

		idx := r % system.BUF_COUNT

		req := buffers[idx].ReqId
		len := buffers[idx].Length
		buffer := buffers[idx].Data[:len]

		// resolver packet buffer
		entity := &pb.ProducerData{}
		if err := proto.Unmarshal(buffer, entity); err == nil {
			ch <- c{
				id:     req,
				buffer: resolver.ExecuteProto(entity),
			}
		}
		//fmt.Println("worker Received:", req)
		atomic.CompareAndSwapUint64(&header.ReadIdx, r, r+1)
	}
}

func callBack(addr []byte) {
	header, buffers := system.GetShmPointers(uintptr(unsafe.Pointer(&addr[0])))
	header.WriteIdx = 0
	header.ReadIdx = 0
	futex := (*sem.Semaphore)(unsafe.Pointer(&header.Futex))
	defer futex.Destroy()

	for {
		select {
		case <-sigCh:
			return
		case data := <-ch:
			var w uint64
			for {

				r := atomic.LoadUint64(&header.ReadIdx)
				w = atomic.LoadUint64(&header.WriteIdx)

				if w-r >= system.BUF_COUNT {
					ipc.SchedYield()
					continue
				}
				break
			}
			idx := header.WriteIdx % system.BUF_COUNT
			bytes, err := proto.Marshal(data.buffer)
			if err == nil {
				buffers[idx].ReqId = data.id
				buffers[idx].Length = uint32(len(bytes))
				copy(buffers[idx].Data[:], bytes)
			}

			atomic.CompareAndSwapUint64(&header.WriteIdx, w, w+1)
			futex.PostWithRetry(3)
			//fmt.Println("worker Send:", data.id)
		}
	}
}
