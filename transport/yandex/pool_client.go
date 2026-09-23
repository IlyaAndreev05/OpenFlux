package yandex

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"openflux/transport"
	"openflux/utils"
)

const (
	poolHeartbeatInterval = 2 * time.Second
	poolHeartbeatTimeout  = 10 * time.Second
	poolHandshakeTimeout  = 15 * time.Second
)

type controlResult struct {
	source string
	frame  poolFrame
}

type YandexDocsPoolClient struct {
	*transport.BaseTransport
	cfg       PoolConfig
	tc        transport.TransportConfig
	domain    string
	cipher    *poolCipher
	sessionID [16]byte

	mu       sync.RWMutex
	rawDocs  map[string]*YandexDocsTransport
	activeID string
	epoch    uint64

	assignCh chan controlResult
	readyCh  chan controlResult
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	lifeMu   sync.Mutex
	started  bool
	stopped  bool
	lastAck  atomic.Int64
}

func NewYandexDocsPoolClient(cfg PoolConfig, tc transport.TransportConfig) (*YandexDocsPoolClient, error) {
	cipher, err := newPoolCipher(cfg.ClientKey, poolDomain(cfg), cfg.ClientID, false)
	if err != nil {
		return nil, err
	}
	tc = boundedPoolTransportConfig(tc)
	c := &YandexDocsPoolClient{
		BaseTransport: transport.NewBaseTransport(tc),
		cfg:           cfg, tc: tc, domain: poolDomain(cfg), cipher: cipher,
		rawDocs:  make(map[string]*YandexDocsTransport),
		assignCh: make(chan controlResult, 16), readyCh: make(chan controlResult, 16),
		stopCh: make(chan struct{}),
	}
	return c, nil
}

func (c *YandexDocsPoolClient) Start() error {
	c.lifeMu.Lock()
	if c.started || c.stopped {
		c.lifeMu.Unlock()
		return errors.New("Yandex Docs pool client cannot be started more than once")
	}
	if _, err := rand.Read(c.sessionID[:]); err != nil {
		c.lifeMu.Unlock()
		return fmt.Errorf("create pool session id: %w", err)
	}
	if err := c.BaseTransport.Start(); err != nil {
		c.lifeMu.Unlock()
		return err
	}
	c.started = true
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.connectLoop()
	}()
	c.lifeMu.Unlock()
	return nil
}

func (c *YandexDocsPoolClient) Stop() error {
	c.lifeMu.Lock()
	if c.stopped {
		c.lifeMu.Unlock()
		return nil
	}
	c.stopped = true
	c.stopOnce.Do(func() { close(c.stopCh) })
	c.mu.RLock()
	docID, epoch := c.activeID, c.epoch
	raw := c.rawDocs[docID]
	c.mu.RUnlock()
	if raw != nil {
		closeFrame := poolFrame{Kind: poolClose, Direction: 0, ClientID: c.cfg.ClientID, SessionID: c.sessionID, Epoch: epoch, DocID: docID}
		closeFrame.Payload = poolProof(c.cfg.ClientKey, c.domain, closeFrame)
		if encoded, err := encodePoolFrame(closeFrame); err == nil {
			_ = raw.Send(encoded)
		}
	}
	c.SetConnected(false)
	_ = c.BaseTransport.Stop()
	c.lifeMu.Unlock()
	c.closeAllRaw()
	c.wg.Wait()
	return nil
}

func (c *YandexDocsPoolClient) Send(data []byte) error {
	if !c.IsConnected() {
		return errors.New("Yandex Docs pool is not connected")
	}
	c.mu.RLock()
	docID, epoch := c.activeID, c.epoch
	raw := c.rawDocs[docID]
	c.mu.RUnlock()
	if raw == nil || !raw.IsConnected() {
		return errors.New("assigned Yandex document is disconnected")
	}
	f, err := c.cipher.seal(poolFrame{Kind: poolData, ClientID: c.cfg.ClientID, SessionID: c.sessionID, Epoch: epoch, DocID: docID}, data)
	if err != nil {
		return err
	}
	encoded, err := encodePoolFrame(f)
	if err != nil {
		return err
	}
	if err := raw.Send(encoded); err != nil {
		return err
	}
	c.RecordSend(len(data))
	return nil
}

func (c *YandexDocsPoolClient) connectLoop() {
	start := stickyIndex(c.cfg.ClientID, c.cfg.Docs)
	for c.IsRunning() {
		connected := false
		for n := 0; n < len(c.cfg.Docs) && c.IsRunning(); n++ {
			index := (start + n) % len(c.cfg.Docs)
			docID := c.cfg.Docs[index].ID
			if err := c.establish(docID); err != nil {
				c.closeAllRaw()
				continue
			}
			connected = true
			c.mu.RLock()
			activeID := c.activeID
			c.mu.RUnlock()
			start = c.docIndex(activeID)
			if c.runActive() {
				start = (start + 1) % len(c.cfg.Docs)
			}
			c.SetConnected(false)
			c.closeAllRaw()
			break
		}
		if !connected && c.IsRunning() {
			select {
			case <-time.After(time.Second):
			case <-c.stopCh:
				return
			}
		}
	}
}

func (c *YandexDocsPoolClient) establish(bootstrap string) error {
	drainControl(c.assignCh)
	drainControl(c.readyCh)
	raw, err := c.startRaw(bootstrap)
	if err != nil {
		return err
	}
	if !c.waitRaw(raw, poolHandshakeTimeout) {
		return fmt.Errorf("document %q did not connect", bootstrap)
	}

	hello := poolFrame{Kind: poolHello, Direction: 0, ClientID: c.cfg.ClientID, SessionID: c.sessionID, DocID: bootstrap}
	hello.Payload = poolProof(c.cfg.ClientKey, c.domain, hello)
	assign, err := c.sendUntilControl(raw, hello, c.assignCh, bootstrap, 0, "")
	if err != nil {
		return err
	}
	target := assign.frame.DocID
	if c.docIndex(target) < 0 {
		return fmt.Errorf("exit assigned unknown document %q", target)
	}
	targetRaw := raw
	if target != bootstrap {
		targetRaw, err = c.startRaw(target)
		if err != nil {
			return err
		}
		if !c.waitRaw(targetRaw, poolHandshakeTimeout) {
			return fmt.Errorf("assigned document %q did not connect", target)
		}
	}
	bind := poolFrame{Kind: poolBind, Direction: 0, ClientID: c.cfg.ClientID, SessionID: c.sessionID, Epoch: assign.frame.Epoch, DocID: target}
	bind.Payload = poolProof(c.cfg.ClientKey, c.domain, bind)
	if _, err := c.sendUntilControl(targetRaw, bind, c.readyCh, target, assign.frame.Epoch, target); err != nil {
		return err
	}
	if target != bootstrap {
		c.dropRaw(bootstrap)
	}

	c.mu.Lock()
	c.activeID = target
	c.epoch = assign.frame.Epoch
	c.mu.Unlock()
	c.lastAck.Store(time.Now().UnixNano())
	c.SetConnected(true)
	utils.Debugf("[POOL] client %s connected to document %s (epoch %d)", c.cfg.ClientID, target, assign.frame.Epoch)
	return nil
}

func (c *YandexDocsPoolClient) sendUntilControl(raw *YandexDocsTransport, frame poolFrame, ch <-chan controlResult, source string, epoch uint64, docID string) (controlResult, error) {
	encoded, err := encodePoolFrame(frame)
	if err != nil {
		return controlResult{}, err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	deadline := time.NewTimer(poolHandshakeTimeout)
	defer deadline.Stop()
	for {
		if err := raw.Send(encoded); err != nil && !raw.IsConnected() {
			return controlResult{}, err
		}
		select {
		case result := <-ch:
			if result.source != source || result.frame.ClientID != c.cfg.ClientID || result.frame.SessionID != c.sessionID {
				continue
			}
			if epoch != 0 && result.frame.Epoch != epoch {
				continue
			}
			if docID != "" && result.frame.DocID != docID {
				continue
			}
			if !verifyPoolProof(c.cfg.ClientKey, c.domain, result.frame) {
				continue
			}
			return result, nil
		case <-ticker.C:
			if !raw.IsConnected() {
				return controlResult{}, errors.New("Yandex document disconnected during handshake")
			}
		case <-deadline.C:
			return controlResult{}, errors.New("Yandex pool handshake timed out")
		case <-c.stopCh:
			return controlResult{}, errors.New("Yandex Docs pool stopped")
		}
	}
}

func (c *YandexDocsPoolClient) runActive() bool {
	ticker := time.NewTicker(poolHeartbeatInterval)
	defer ticker.Stop()
	for c.IsRunning() {
		select {
		case <-ticker.C:
			c.mu.RLock()
			docID, epoch := c.activeID, c.epoch
			raw := c.rawDocs[docID]
			c.mu.RUnlock()
			if raw == nil || !raw.IsConnected() || time.Since(time.Unix(0, c.lastAck.Load())) >= poolHeartbeatTimeout {
				return true
			}
			ping := poolFrame{Kind: poolPing, Direction: 0, ClientID: c.cfg.ClientID, SessionID: c.sessionID, Epoch: epoch, DocID: docID}
			ping.Payload = poolProof(c.cfg.ClientKey, c.domain, ping)
			encoded, err := encodePoolFrame(ping)
			if err != nil || raw.Send(encoded) != nil {
				return true
			}
		case <-c.stopCh:
			return false
		}
	}
	return false
}

func (c *YandexDocsPoolClient) startRaw(docID string) (*YandexDocsTransport, error) {
	c.mu.Lock()
	if existing := c.rawDocs[docID]; existing != nil {
		c.mu.Unlock()
		return existing, nil
	}
	var doc *PoolDocument
	for i := range c.cfg.Docs {
		if c.cfg.Docs[i].ID == docID {
			doc = &c.cfg.Docs[i]
			break
		}
	}
	if doc == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("unknown Yandex document %q", docID)
	}
	raw := NewYandexDocsTransport(doc.URL, c.tc)
	raw.Receive(func(data []byte) { c.handleRawData(docID, data) })
	c.rawDocs[docID] = raw
	c.mu.Unlock()
	if err := raw.Start(); err != nil {
		c.mu.Lock()
		delete(c.rawDocs, docID)
		c.mu.Unlock()
		return nil, err
	}
	return raw, nil
}

func (c *YandexDocsPoolClient) handleRawData(source string, data []byte) {
	f, err := decodePoolFrame(data)
	if err != nil || f.ClientID != c.cfg.ClientID || f.SessionID != c.sessionID || f.Direction != 1 {
		return
	}
	switch f.Kind {
	case poolAssign:
		select {
		case c.assignCh <- controlResult{source: source, frame: f}:
		default:
		}
	case poolReady:
		select {
		case c.readyCh <- controlResult{source: source, frame: f}:
		default:
		}
	case poolPong:
		if !verifyPoolProof(c.cfg.ClientKey, c.domain, f) {
			return
		}
		c.mu.RLock()
		matches := source == c.activeID && f.DocID == c.activeID && f.Epoch == c.epoch
		c.mu.RUnlock()
		if matches {
			c.lastAck.Store(time.Now().UnixNano())
		}
	case poolData:
		c.mu.RLock()
		matches := source == c.activeID && f.DocID == c.activeID && f.Epoch == c.epoch
		c.mu.RUnlock()
		if !matches {
			return
		}
		plain, err := c.cipher.open(f)
		if err != nil {
			return
		}
		c.RecordReceive(len(plain))
		c.CallReceive(plain)
	}
}

func (c *YandexDocsPoolClient) waitRaw(raw *YandexDocsTransport, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if raw.IsConnected() {
			return true
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			return false
		case <-c.stopCh:
			return false
		}
	}
}

func (c *YandexDocsPoolClient) dropRaw(docID string) {
	c.mu.Lock()
	raw := c.rawDocs[docID]
	delete(c.rawDocs, docID)
	c.mu.Unlock()
	if raw != nil {
		_ = raw.Stop()
	}
}

func (c *YandexDocsPoolClient) closeAllRaw() {
	c.mu.Lock()
	raws := make([]*YandexDocsTransport, 0, len(c.rawDocs))
	for _, raw := range c.rawDocs {
		raws = append(raws, raw)
	}
	c.rawDocs = make(map[string]*YandexDocsTransport)
	c.activeID = ""
	c.mu.Unlock()
	for _, raw := range raws {
		_ = raw.Stop()
	}
}

func (c *YandexDocsPoolClient) docIndex(id string) int {
	for i, doc := range c.cfg.Docs {
		if doc.ID == id {
			return i
		}
	}
	return -1
}

func drainControl(ch chan controlResult) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (c *YandexDocsPoolClient) Stats() transport.TransportStats { return c.BaseTransport.Stats() }
