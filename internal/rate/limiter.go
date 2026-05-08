package rate

import (
	"context"
	"time"
)

type Limiter struct {
	ticker *time.Ticker
	off    bool
}

func New(perSecond int) *Limiter {
	if perSecond <= 0 {
		return &Limiter{off: true}
	}
	interval := time.Second / time.Duration(perSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return &Limiter{ticker: time.NewTicker(interval)}
}

func (l *Limiter) Wait(ctx context.Context) {
	if l == nil || l.off {
		return
	}
	select {
	case <-ctx.Done():
	case <-l.ticker.C:
	}
}

func (l *Limiter) Stop() {
	if l != nil && l.ticker != nil {
		l.ticker.Stop()
	}
}
