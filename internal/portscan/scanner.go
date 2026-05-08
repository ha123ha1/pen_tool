package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type OpenPort struct {
	Port int
}

func Scan(ctx context.Context, host string, ports []int, concurrency int, timeout time.Duration) ([]OpenPort, error) {
	if concurrency <= 0 {
		concurrency = 100
	}
	jobs := make(chan int)
	results := make(chan OpenPort)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var d net.Dialer
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				dialCtx := ctx
				cancel := func() {}
				if timeout > 0 {
					dialCtx, cancel = context.WithTimeout(ctx, timeout)
				}
				conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprint(p)))
				cancel()
				if err == nil {
					_ = conn.Close()
					results <- OpenPort{Port: p}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case <-ctx.Done():
				return
			case jobs <- p:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	var open []OpenPort
	for r := range results {
		open = append(open, r)
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open, ctx.Err()
}
