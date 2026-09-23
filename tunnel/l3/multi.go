package l3

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"openflux/transport"
	"openflux/utils"
)

const maxMultiClientFlows = 262_144

type clientFlowKey struct {
	clientID string
	flow     flowKey
}

type remoteEndpoint struct {
	ip   uint32
	port uint16
}

type replyFlowKey struct {
	remoteIP   uint32
	localIP    uint32
	remotePort uint16
	localPort  uint16
	proto      uint8
}

type multiFlowEntry struct {
	clientID       string
	original       flowKey
	remote         remoteEndpoint
	translatedPort uint16
	lastSeen       time.Time
	dying          bool
}

type MultiClientExit struct {
	backend L3Backend

	mu        sync.RWMutex
	clients   map[string]transport.Transport
	byClient  map[clientFlowKey]*multiFlowEntry
	byReply   map[replyFlowKey]*multiFlowEntry
	ports     map[remoteEndpoint]map[uint16]*multiFlowEntry
	flowCount atomic.Int64
	started   atomic.Bool
	stopCh    chan struct{}
	stopOnce  sync.Once
}

func NewMultiClientExit() (*MultiClientExit, error) {
	backend, err := newBackend()
	if err != nil {
		return nil, err
	}
	return newMultiClientExit(backend), nil
}

func newMultiClientExit(backend L3Backend) *MultiClientExit {
	return &MultiClientExit{
		backend:  backend,
		clients:  make(map[string]transport.Transport),
		byClient: make(map[clientFlowKey]*multiFlowEntry),
		byReply:  make(map[replyFlowKey]*multiFlowEntry),
		ports:    make(map[remoteEndpoint]map[uint16]*multiFlowEntry),
		stopCh:   make(chan struct{}),
	}
}

func (t *MultiClientExit) Start() error {
	if !t.started.CompareAndSwap(false, true) {
		return errors.New("multi-client L3 exit already started")
	}
	t.backend.Recv(t.handleFromInternet)
	go t.sweepLoop()
	utils.Debugf("[POOL-L3] started: egress=%s", ipStr(ipU32(t.backend.EgressIP())))
	return nil
}

func (t *MultiClientExit) AddClient(id string, trans transport.Transport) error {
	if id == "" || trans == nil {
		return errors.New("L3 pool client requires id and transport")
	}
	t.mu.Lock()
	old := t.clients[id]
	t.clients[id] = trans
	t.mu.Unlock()
	if old != nil && old != trans {
		_ = old.Stop()
	}
	trans.Receive(func(pkt []byte) { t.handleFromClient(id, pkt) })
	return nil
}

func (t *MultiClientExit) RemoveClient(id string) {
	t.mu.Lock()
	trans := t.clients[id]
	delete(t.clients, id)
	for key, entry := range t.byClient {
		if key.clientID == id {
			t.deleteEntryLocked(key, entry)
		}
	}
	t.mu.Unlock()
	if trans != nil {
		_ = trans.Stop()
	}
}

func (t *MultiClientExit) Stop() error {
	t.stopOnce.Do(func() { close(t.stopCh) })
	t.mu.Lock()
	clients := make([]transport.Transport, 0, len(t.clients))
	for _, trans := range t.clients {
		clients = append(clients, trans)
	}
	t.clients = make(map[string]transport.Transport)
	t.byClient = make(map[clientFlowKey]*multiFlowEntry)
	t.byReply = make(map[replyFlowKey]*multiFlowEntry)
	t.ports = make(map[remoteEndpoint]map[uint16]*multiFlowEntry)
	t.flowCount.Store(0)
	t.mu.Unlock()
	for _, trans := range clients {
		_ = trans.Stop()
	}
	return t.backend.Close()
}

func (t *MultiClientExit) handleFromClient(clientID string, pkt []byte) {
	sl, ok := sliceIPv4(pkt)
	if !ok || len(sl) < 20 || sl[9] != 6 {
		return
	}
	pkt = append([]byte(nil), sl...)
	if pkt[12] != clientIPBytes[0] || pkt[13] != clientIPBytes[1] ||
		pkt[14] != clientIPBytes[2] || pkt[15] != clientIPBytes[3] {
		return
	}
	if isTCPRST(pkt) {
		return
	}
	key, ok := extractFlowKey(pkt)
	if !ok {
		return
	}
	ck := clientFlowKey{clientID: clientID, flow: key}
	egress := t.backend.EgressIP()
	egressIP := ipU32(egress)
	var entry *multiFlowEntry
	t.mu.Lock()
	entry = t.byClient[ck]
	if entry == nil {
		if t.flowCount.Load() >= maxMultiClientFlows {
			t.mu.Unlock()
			utils.Debugf("[POOL-L3] flow limit reached")
			return
		}
		remote := remoteEndpoint{ip: key.dstIP, port: key.dstPort}
		port, err := t.allocatePortLocked(remote, key.srcPort)
		if err != nil {
			t.mu.Unlock()
			utils.Debugf("[POOL-L3] allocate NAT port: %v", err)
			return
		}
		entry = &multiFlowEntry{
			clientID: clientID, original: key, remote: remote,
			translatedPort: port, lastSeen: time.Now(),
		}
		t.byClient[ck] = entry
		if t.ports[remote] == nil {
			t.ports[remote] = make(map[uint16]*multiFlowEntry)
		}
		t.ports[remote][port] = entry
		rk := replyFlowKey{remoteIP: remote.ip, localIP: egressIP, remotePort: remote.port, localPort: port, proto: 6}
		t.byReply[rk] = entry
		t.flowCount.Add(1)
	}
	entry.lastSeen = time.Now()
	if isTCPClosing(pkt) {
		entry.dying = true
	}
	port := entry.translatedPort
	t.mu.Unlock()

	pkt[12], pkt[13], pkt[14], pkt[15] = egress[0], egress[1], egress[2], egress[3]
	ihl := int(pkt[0]&0x0f) * 4
	pkt[ihl], pkt[ihl+1] = byte(port>>8), byte(port)
	fixChecksums(pkt)
	if err := t.backend.Send(pkt); err != nil {
		utils.Debugf("[POOL-L3] send to network failed: %v", err)
	}
}

func (t *MultiClientExit) allocatePortLocked(remote remoteEndpoint, preferred uint16) (uint16, error) {
	used := t.ports[remote]
	if preferred >= 1024 && used[preferred] == nil {
		return preferred, nil
	}
	const first = uint32(1024)
	for i := uint32(0); i < 65536-first; i++ {
		port := uint16(first + i)
		if used[port] == nil {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free source ports for %s:%d", ipStr(remote.ip), remote.port)
}

func (t *MultiClientExit) handleFromInternet(pkt []byte) {
	sl, ok := sliceIPv4(pkt)
	if !ok || len(sl) < 40 || sl[9] != 6 {
		return
	}
	pkt = append([]byte(nil), sl...)
	egress := t.backend.EgressIP()
	if pkt[16] != egress[0] || pkt[17] != egress[1] ||
		pkt[18] != egress[2] || pkt[19] != egress[3] {
		return
	}
	key, ok := extractFlowKey(pkt)
	if !ok {
		return
	}
	rk := replyFlowKey{
		remoteIP: key.srcIP, localIP: key.dstIP,
		remotePort: key.srcPort, localPort: key.dstPort, proto: key.proto,
	}
	t.mu.Lock()
	entry := t.byReply[rk]
	if entry == nil {
		t.mu.Unlock()
		return
	}
	entry.lastSeen = time.Now()
	if isTCPClosing(pkt) {
		entry.dying = true
	}
	clientID, originalPort := entry.clientID, entry.original.srcPort
	trans := t.clients[clientID]
	t.mu.Unlock()
	if trans == nil {
		return
	}
	copy(pkt[16:20], clientIPBytes[:])
	ihl := int(pkt[0]&0x0f) * 4
	pkt[ihl+2], pkt[ihl+3] = byte(originalPort>>8), byte(originalPort)
	fixChecksums(pkt)
	if err := trans.Send(pkt); err != nil {
		utils.Debugf("[POOL-L3] send to client %s failed: %v", clientID, err)
	}
}

func (t *MultiClientExit) deleteEntryLocked(key clientFlowKey, entry *multiFlowEntry) {
	delete(t.byClient, key)
	rk := replyFlowKey{remoteIP: entry.remote.ip, localIP: ipU32(t.backend.EgressIP()), remotePort: entry.remote.port, localPort: entry.translatedPort, proto: 6}
	delete(t.byReply, rk)
	if ports := t.ports[entry.remote]; ports != nil {
		delete(ports, entry.translatedPort)
		if len(ports) == 0 {
			delete(t.ports, entry.remote)
		}
	}
	t.flowCount.Add(-1)
}

func (t *MultiClientExit) sweepLoop() {
	ticker := time.NewTicker(ctSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case now := <-ticker.C:
			t.mu.Lock()
			for key, entry := range t.byClient {
				timeout := ctTimeoutEstablished
				if entry.dying {
					timeout = ctTimeoutClosing
				}
				if now.Sub(entry.lastSeen) > timeout {
					t.deleteEntryLocked(key, entry)
				}
			}
			t.mu.Unlock()
		}
	}
}
