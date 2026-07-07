package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/argusappsec/argus/pkg/audit"
)

// RunChannels starts one goroutine per Channel (ADR 0004) and blocks until
// ctx is cancelled and every Channel has returned. A panic inside a Channel
// is recovered, audited as channel_panic, and the Channel is restarted with
// exponential backoff; other Channels keep serving. Errors restart the same
// way — a misbehaving transport can degrade itself, never the daemon.
func RunChannels(ctx context.Context, dc *Context, channels ...Channel) {
	var wg sync.WaitGroup
	for _, ch := range channels {
		wg.Add(1)
		go func(ch Channel) {
			defer wg.Done()
			backoff := time.Second
			for {
				err := startOnce(ctx, dc, ch)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					_ = dc.Audit.Log(audit.Event{Type: "channel_error", Data: map[string]any{
						"channel": ch.Name(),
						"error":   err.Error(),
					}})
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
		}(ch)
	}
	wg.Wait()
}

// startOnce runs one Channel.Start invocation behind a recover fence.
func startOnce(ctx context.Context, dc *Context, ch Channel) (err error) {
	defer func() {
		if r := recover(); r != nil {
			_ = dc.Audit.Log(audit.Event{Type: "channel_panic", Data: map[string]any{
				"channel": ch.Name(),
				"panic":   fmt.Sprint(r),
			}})
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return ch.Start(ctx)
}
