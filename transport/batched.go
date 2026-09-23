package transport

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"openflux/utils"
)

// Defaults for the coalescing layer. Tunable at runtime via env vars so the
// batch size can be matched to the channel's per-message limits without a
// rebuild (OPENFLUX_BATCH_BYTES / OPENFLUX_BATCH_COUNT / OPENFLUX_BATCH_LINGER_MS).
const (
	defaultMaxBatchBytes = 8192
	defaultMaxBatchCount = 64
	defaultLingerMs      = 5
	batchQueueDepth      = 4096
)

// BatchedTransport replaces the old per-packet CompressedTransport. It queues
// outgoing tunnel packets, coalesces bursts into a single framed+zstd batch per
// inner transport message, and splits batches back into packets on receive.
//
// This is the symmetric layer: client and exit node must both use it (they do,
// because main.go wraps both the same way).
type BatchedTransport struct {
	Transport

	queue         chan []byte
	lingerMs      int
	maxBatchBytes int
	maxBatchCount int

	running  atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	lifeMu   sync.Mutex
	started  bool
	stopped  bool

	mu     sync.RWMutex
	userCb func([]byte)
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func NewBatchedTransport(inner Transport) *BatchedTransport {
	return NewBatchedTransportWithQueue(inner, batchQueueDepth)
}

// NewBatchedTransportWithQueue creates a batching layer with a bounded number
// of pending packets. Pool mode uses a smaller queue because it may create up
// to a thousand independent client transports in one process.
func NewBatchedTransportWithQueue(inner Transport, queueDepth int) *BatchedTransport {
	if queueDepth < 1 {
		queueDepth = batchQueueDepth
	}
	return &BatchedTransport{
		Transport:     inner,
		queue:         make(chan []byte, queueDepth),
		lingerMs:      envInt("OPENFLUX_BATCH_LINGER_MS", defaultLingerMs),
		maxBatchBytes: envInt("OPENFLUX_BATCH_BYTES", defaultMaxBatchBytes),
		maxBatchCount: envInt("OPENFLUX_BATCH_COUNT", defaultMaxBatchCount),
		stopCh:        make(chan struct{}),
	}
}

func (b *BatchedTransport) Start() error {
	b.lifeMu.Lock()
	defer b.lifeMu.Unlock()
	if b.started || b.stopped {
		return fmt.Errorf("batched transport cannot be started more than once")
	}
	if err := b.Transport.Start(); err != nil {
		return err
	}
	b.started = true
	b.running.Store(true)
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.flushLoop()
	}()
	return nil
}

func (b *BatchedTransport) Stop() error {
	b.lifeMu.Lock()
	if b.stopped {
		b.lifeMu.Unlock()
		return nil
	}
	b.stopped = true
	b.running.Store(false)
	b.stopOnce.Do(func() { close(b.stopCh) })
	started := b.started
	b.lifeMu.Unlock()
	b.wg.Wait()
	if started {
		return b.Transport.Stop()
	}
	return nil
}

// Send copies the packet (the caller's buffer is reused by gVisor) and enqueues
// it for batching. A full queue drops the packet; the tunnel's TCP will
// retransmit, same as the old "write queue full" behavior.
func (b *BatchedTransport) Send(data []byte) error {
	b.lifeMu.Lock()
	defer b.lifeMu.Unlock()
	if !b.running.Load() {
		return fmt.Errorf("batched transport is not running")
	}
	p := make([]byte, len(data))
	copy(p, data)
	select {
	case b.queue <- p:
		return nil
	default:
		return fmt.Errorf("batch queue full")
	}
}

func (b *BatchedTransport) Receive(callback func([]byte)) {
	b.mu.Lock()
	b.userCb = callback
	b.mu.Unlock()

	b.Transport.Receive(func(data []byte) {
		pkts, err := decodeBatch(data)
		if err != nil {
			utils.Debugf("[BATCH] decode error (%d bytes): %v", len(data), err)
			return
		}
		b.mu.RLock()
		cb := b.userCb
		b.mu.RUnlock()
		if cb == nil {
			return
		}
		for _, p := range pkts {
			cb(p)
		}
	})
}

func (b *BatchedTransport) flushLoop() {
	for b.running.Load() {
		var first []byte
		select {
		case first = <-b.queue:
		case <-b.stopCh:
			return
		}
		batch := [][]byte{first}
		size := 2 + len(first)

		// Phase 1: absorb everything already queued (burst coalescing). This
		// alone collapses a window's worth of segments into one message.
	drainNow:
		for size < b.maxBatchBytes && len(batch) < b.maxBatchCount {
			select {
			case p := <-b.queue:
				batch = append(batch, p)
				size += 2 + len(p)
			default:
				break drainNow
			}
		}

		// Phase 2: brief linger to catch stragglers arriving just after the
		// burst. Negligible next to the channel RTT, but it fills batches
		// during steady bulk transfer.
		if b.lingerMs > 0 && size < b.maxBatchBytes && len(batch) < b.maxBatchCount {
			timer := time.NewTimer(time.Duration(b.lingerMs) * time.Millisecond)
		linger:
			for size < b.maxBatchBytes && len(batch) < b.maxBatchCount {
				select {
				case p := <-b.queue:
					batch = append(batch, p)
					size += 2 + len(p)
				case <-timer.C:
					break linger
				case <-b.stopCh:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return
				}
			}
			timer.Stop()
		}

		b.Transport.Send(encodeBatch(batch))
	}
}
