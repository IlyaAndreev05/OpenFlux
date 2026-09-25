package yandex

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"openflux/transport"
	"openflux/utils"
)

const (
	poolSessionTimeout = 30 * time.Second
	poolRawQueueSize   = 16
)

func boundedPoolTransportConfig(tc transport.TransportConfig) transport.TransportConfig {
	if tc.MaxQueueSize <= 0 || tc.MaxQueueSize > poolRawQueueSize {
		tc.MaxQueueSize = poolRawQueueSize
	}
	return tc
}

type YandexDocsPoolServer struct {
	cfg       PoolConfig
	transport transport.TransportConfig
	domain    string
	onClient  func(*PoolSession)
	onRemove  func(string)

	startMu  sync.Mutex
	started  bool
	stopped  bool
	mu       sync.RWMutex
	docs     map[string]*YandexDocsTransport
	sessions map[string]*PoolSession
	nextRR   uint64
	running  atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once
}

type PoolSession struct {
	*transport.BaseTransport
	server    *YandexDocsPoolServer
	clientID  string
	sessionID [16]byte
	key       [32]byte
	cipher    *poolCipher

	mu               sync.RWMutex
	epoch            uint64
	docID            string
	active           bool
	pendingEpoch     uint64
	pendingDoc       string
	pendingBootstrap string
	pendingChallenge [16]byte
	pendingCipher    *poolCipher
	announced        bool
	helloSeen        map[[16]byte]struct{}
	helloFIFO        [][16]byte
	pingSeen         map[[16]byte]struct{}
	pingFIFO         [][16]byte
	lastSeen         time.Time
}

func NewYandexDocsPoolServer(cfg PoolConfig, tc transport.TransportConfig, onClient func(*PoolSession), onRemove func(string)) *YandexDocsPoolServer {
	tc = boundedPoolTransportConfig(tc)
	return &YandexDocsPoolServer{
		cfg: cfg, transport: tc, domain: poolDomain(cfg),
		onClient: onClient, onRemove: onRemove,
		docs:     make(map[string]*YandexDocsTransport, len(cfg.Docs)),
		sessions: make(map[string]*PoolSession),
		stopCh:   make(chan struct{}),
	}
}

func (s *YandexDocsPoolServer) Start() error {
	s.startMu.Lock()
	if s.started || s.stopped {
		s.startMu.Unlock()
		return errors.New("Yandex Docs pool server cannot be started more than once")
	}
	s.started = true
	s.running.Store(true)
	for _, doc := range s.cfg.Docs {
		id := doc.ID
		raw := NewYandexDocsTransport(doc.URL, s.transport)
		raw.Receive(func(data []byte) { s.handleDocData(id, data) })
		s.mu.Lock()
		s.docs[id] = raw
		s.mu.Unlock()
		if err := raw.Start(); err != nil {
			_ = s.Stop()
			return fmt.Errorf("start document %q: %w", id, err)
		}
	}
	go s.sweepLoop()
	return nil
}

func (s *YandexDocsPoolServer) Stop() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.running.Store(false)
	})
	s.mu.Lock()
	docs := make([]*YandexDocsTransport, 0, len(s.docs))
	for _, d := range s.docs {
		docs = append(docs, d)
	}
	sessions := make([]*PoolSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.docs = make(map[string]*YandexDocsTransport)
	s.sessions = make(map[string]*PoolSession)
	s.mu.Unlock()
	for _, session := range sessions {
		session.SetConnected(false)
		_ = session.BaseTransport.Stop()
		session.mu.RLock()
		announced := session.announced
		session.mu.RUnlock()
		if announced && s.onRemove != nil {
			s.onRemove(session.clientID)
		}
	}
	for _, d := range docs {
		_ = d.Stop()
	}
	return nil
}

func (s *YandexDocsPoolServer) handleDocData(docID string, data []byte) {
	if !s.running.Load() {
		return
	}
	f, err := decodePoolFrame(data)
	if err != nil || f.Direction != 0 || f.Version != effectivePoolVersion(s.cfg) {
		return
	}
	switch f.Kind {
	case poolHello:
		s.handleHello(docID, f)
	case poolBind:
		s.handleBind(docID, f)
	case poolPing:
		s.handlePing(docID, f)
	case poolData:
		s.handleData(docID, f)
	case poolClose:
		s.handleClose(f)
	}
}

func (s *YandexDocsPoolServer) handleHello(bootstrap string, f poolFrame) {
	key, ok := s.cfg.Clients[f.ClientID]
	if !ok || f.Version != effectivePoolVersion(s.cfg) || f.DocID != bootstrap || !verifyPoolProof(key, s.domain, f) {
		return
	}
	if f.Version == poolProtocolCurrent && f.Challenge == [16]byte{} {
		return
	}

	var replaced *PoolSession
	var replacedAnnounced bool
	s.mu.Lock()
	if !s.running.Load() {
		s.mu.Unlock()
		return
	}
	session := s.sessions[f.ClientID]
	if session != nil && session.sessionID != f.SessionID {
		session.mu.RLock()
		last, active, docID, announced := session.lastSeen, session.active, session.docID, session.announced
		session.mu.RUnlock()
		raw := s.docs[docID]
		if active && time.Since(last) <= poolSessionTimeout && raw != nil && raw.IsConnected() {
			// A valid but stale HELLO must never evict a live session.
			s.mu.Unlock()
			return
		}
		replaced, replacedAnnounced = session, announced
		delete(s.sessions, f.ClientID)
		session = nil
	}
	if session == nil {
		if len(s.sessions) >= MaxPoolClients {
			s.mu.Unlock()
			return
		}
		session = &PoolSession{
			BaseTransport: transport.NewBaseTransport(s.transport),
			server:        s, clientID: f.ClientID, sessionID: f.SessionID, key: key,
			helloSeen: make(map[[16]byte]struct{}), pingSeen: make(map[[16]byte]struct{}),
		}
		s.sessions[f.ClientID] = session
	}

	session.mu.Lock()
	needTarget := false
	if f.Version == poolProtocolCurrent {
		if f.Challenge != session.pendingChallenge {
			if _, replay := session.helloSeen[f.Challenge]; replay {
				session.mu.Unlock()
				s.mu.Unlock()
				return
			}
			session.helloSeen[f.Challenge] = struct{}{}
			session.helloFIFO = append(session.helloFIFO, f.Challenge)
			if len(session.helloFIFO) > poolReplayLimit {
				old := session.helloFIFO[0]
				session.helloFIFO = session.helloFIFO[1:]
				delete(session.helloSeen, old)
			}
			var epochBytes [8]byte
			if _, err := rand.Read(epochBytes[:]); err != nil {
				session.mu.Unlock()
				s.mu.Unlock()
				return
			}
			epoch := binary.BigEndian.Uint64(epochBytes[:])
			if epoch == 0 || epoch == session.epoch {
				epoch++
			}
			cipher, err := newPoolSessionCipher(key, s.domain, f.ClientID, true, f.Version, f.SessionID, epoch)
			if err != nil {
				session.mu.Unlock()
				s.mu.Unlock()
				return
			}
			session.pendingEpoch = epoch
			session.pendingDoc = ""
			session.pendingBootstrap = bootstrap
			session.pendingChallenge = f.Challenge
			session.pendingCipher = cipher
			needTarget = true
		}
	} else if session.pendingBootstrap != bootstrap || session.pendingEpoch == 0 {
		session.pendingDoc = ""
		session.pendingBootstrap = bootstrap
		session.pendingEpoch = session.epoch + 1
		if session.pendingEpoch == 0 {
			session.pendingEpoch = 1
		}
		session.pendingChallenge = [16]byte{}
		session.pendingCipher = nil
		needTarget = true
	}
	epoch := session.pendingEpoch
	challenge := session.pendingChallenge
	session.mu.Unlock()

	if needTarget {
		target := s.chooseDocLocked(f.ClientID, bootstrap)
		if target == "" {
			target = bootstrap
		}
		session.mu.Lock()
		if session.pendingEpoch == epoch && session.pendingChallenge == challenge {
			session.pendingDoc = target
		}
		session.mu.Unlock()
	}
	session.mu.RLock()
	epoch, target, challenge := session.pendingEpoch, session.pendingDoc, session.pendingChallenge
	session.mu.RUnlock()
	s.mu.Unlock()

	if replaced != nil {
		replaced.SetConnected(false)
		_ = replaced.BaseTransport.Stop()
		if replacedAnnounced && s.onRemove != nil {
			s.onRemove(replaced.clientID)
		}
	}
	reply := poolFrame{Version: f.Version, Kind: poolAssign, Direction: 1, ClientID: f.ClientID, SessionID: f.SessionID, Epoch: epoch, Challenge: challenge, DocID: target}
	reply.Payload = poolProof(key, s.domain, reply)
	s.sendControl(bootstrap, reply)
}

func (s *YandexDocsPoolServer) handleBind(docID string, f poolFrame) {
	s.mu.RLock()
	session := s.sessions[f.ClientID]
	s.mu.RUnlock()
	if session == nil || session.sessionID != f.SessionID || !verifyPoolProof(session.key, s.domain, f) {
		return
	}
	session.mu.Lock()
	if f.Epoch != session.pendingEpoch || f.DocID != session.pendingDoc || docID != session.pendingDoc ||
		(f.Version == poolProtocolCurrent && (f.Challenge != session.pendingChallenge || session.pendingCipher == nil)) {
		session.mu.Unlock()
		return
	}
	firstBind := !session.announced
	session.epoch = session.pendingEpoch
	session.docID = session.pendingDoc
	session.active = true
	if f.Version == poolProtocolCurrent {
		session.cipher = session.pendingCipher
	}
	session.pendingEpoch = 0
	session.pendingDoc = ""
	session.pendingBootstrap = ""
	session.pendingChallenge = [16]byte{}
	session.pendingCipher = nil
	session.lastSeen = time.Now()
	session.announced = true
	session.SetConnected(true)
	session.mu.Unlock()

	if firstBind {
		_ = session.BaseTransport.Start()
		if s.onClient != nil {
			s.onClient(session)
		}
	}
	utils.Debugf("[POOL] client %s assigned document %s (epoch %d)", f.ClientID, docID, f.Epoch)
	reply := poolFrame{Version: f.Version, Kind: poolReady, Direction: 1, ClientID: f.ClientID, SessionID: f.SessionID, Epoch: f.Epoch, Challenge: f.Challenge, DocID: docID}
	reply.Payload = poolProof(session.key, s.domain, reply)
	s.sendControl(docID, reply)
}

func (s *YandexDocsPoolServer) handlePing(docID string, f poolFrame) {
	s.mu.RLock()
	session := s.sessions[f.ClientID]
	s.mu.RUnlock()
	if session == nil || session.sessionID != f.SessionID || f.Version != effectivePoolVersion(s.cfg) || !verifyPoolProof(session.key, s.domain, f) {
		return
	}
	session.mu.Lock()
	if !session.active || session.epoch != f.Epoch || session.docID != docID {
		session.mu.Unlock()
		return
	}
	if f.Version == poolProtocolCurrent {
		if f.Challenge == [16]byte{} {
			session.mu.Unlock()
			return
		}
		if _, replay := session.pingSeen[f.Challenge]; replay {
			session.mu.Unlock()
			return
		}
		session.pingSeen[f.Challenge] = struct{}{}
		session.pingFIFO = append(session.pingFIFO, f.Challenge)
		if len(session.pingFIFO) > poolReplayLimit {
			old := session.pingFIFO[0]
			session.pingFIFO = session.pingFIFO[1:]
			delete(session.pingSeen, old)
		}
	}
	session.lastSeen = time.Now()
	session.mu.Unlock()
	reply := poolFrame{Version: f.Version, Kind: poolPong, Direction: 1, ClientID: f.ClientID, SessionID: f.SessionID, Epoch: f.Epoch, Challenge: f.Challenge, DocID: docID}
	reply.Payload = poolProof(session.key, s.domain, reply)
	s.sendControl(docID, reply)
}

func (s *YandexDocsPoolServer) handleData(docID string, f poolFrame) {
	s.mu.RLock()
	session := s.sessions[f.ClientID]
	s.mu.RUnlock()
	if session == nil || session.sessionID != f.SessionID {
		return
	}
	session.mu.RLock()
	active := session.active && session.epoch == f.Epoch && session.docID == docID && f.Version == effectivePoolVersion(s.cfg)
	cipher := session.cipher
	session.mu.RUnlock()
	if !active || cipher == nil {
		return
	}
	plain, err := cipher.open(f)
	if err != nil {
		return
	}
	// Activity is refreshed only after authenticated, non-replayed data and
	// after checking that the same session is still current.
	s.mu.RLock()
	current := s.sessions[f.ClientID] == session
	if current {
		session.mu.Lock()
		current = session.active && session.epoch == f.Epoch && session.docID == docID
		if current {
			session.lastSeen = time.Now()
		}
		session.mu.Unlock()
	}
	s.mu.RUnlock()
	if !current {
		return
	}
	session.RecordReceive(len(plain))
	session.CallReceive(plain)
}

func (s *YandexDocsPoolServer) handleClose(f poolFrame) {
	s.mu.Lock()
	session := s.sessions[f.ClientID]
	if session == nil || session.sessionID != f.SessionID || f.Version != effectivePoolVersion(s.cfg) || !verifyPoolProof(session.key, s.domain, f) {
		s.mu.Unlock()
		return
	}
	session.mu.Lock()
	if !session.active || f.Epoch != session.epoch || f.DocID != session.docID {
		session.mu.Unlock()
		s.mu.Unlock()
		return
	}
	if f.Version == poolProtocolCurrent {
		if f.Challenge == [16]byte{} {
			session.mu.Unlock()
			s.mu.Unlock()
			return
		}
		if _, replay := session.pingSeen[f.Challenge]; replay {
			session.mu.Unlock()
			s.mu.Unlock()
			return
		}
		session.pingSeen[f.Challenge] = struct{}{}
	}
	announced := session.announced
	session.mu.Unlock()
	delete(s.sessions, f.ClientID)
	s.mu.Unlock()
	session.SetConnected(false)
	_ = session.BaseTransport.Stop()
	if announced && s.onRemove != nil {
		s.onRemove(session.clientID)
	}
}

func (s *YandexDocsPoolServer) chooseDocLocked(clientID, fallback string) string {
	available := make([]PoolDocument, 0, len(s.cfg.Docs))
	for _, d := range s.cfg.Docs {
		if raw := s.docs[d.ID]; raw != nil && raw.IsConnected() {
			available = append(available, d)
		}
	}
	if len(available) == 0 {
		return fallback
	}
	loads := make(map[string]int, len(available))
	for _, session := range s.sessions {
		session.mu.RLock()
		if session.pendingDoc != "" {
			loads[session.pendingDoc]++
		} else if session.active {
			loads[session.docID]++
		}
		session.mu.RUnlock()
	}
	return choosePoolDocument(s.cfg.Strategy, clientID, available, loads, &s.nextRR)
}

func choosePoolDocument(strategy, clientID string, available []PoolDocument, loads map[string]int, nextRR *uint64) string {
	if len(available) == 0 {
		return ""
	}
	switch strategy {
	case "round-robin":
		index := *nextRR % uint64(len(available))
		*nextRR++
		return available[index].ID
	case "sticky":
		return available[stickyIndex(clientID, available)].ID
	case "least-loaded", "":
		best := available[0].ID
		for _, d := range available[1:] {
			if loads[d.ID] < loads[best] {
				best = d.ID
			}
		}
		return best
	default:
		return available[0].ID
	}
}

func (s *YandexDocsPoolServer) sendControl(docID string, f poolFrame) {
	data, err := encodePoolFrame(f)
	if err != nil {
		return
	}
	s.mu.RLock()
	raw := s.docs[docID]
	s.mu.RUnlock()
	if raw != nil {
		_ = raw.Send(data)
	}
}

func (s *YandexDocsPoolServer) sendData(session *PoolSession, data []byte) error {
	session.mu.RLock()
	if !session.active || !session.IsRunning() {
		session.mu.RUnlock()
		return errors.New("pool client is not active")
	}
	docID, epoch, sid, cipher := session.docID, session.epoch, session.sessionID, session.cipher
	session.mu.RUnlock()
	if cipher == nil {
		return errors.New("pool client has no active session cipher")
	}
	f, err := cipher.seal(poolFrame{Kind: poolData, ClientID: session.clientID, SessionID: sid, Epoch: epoch, DocID: docID}, data)
	if err != nil {
		return err
	}
	encoded, err := encodePoolFrame(f)
	if err != nil {
		return err
	}
	s.mu.RLock()
	raw := s.docs[docID]
	s.mu.RUnlock()
	if raw == nil || !raw.IsConnected() {
		return errors.New("assigned Yandex document is disconnected")
	}
	if err := raw.Send(encoded); err != nil {
		return err
	}
	session.RecordSend(len(data))
	return nil
}

func (s *YandexDocsPoolServer) sweepLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			var expired []*PoolSession
			s.mu.Lock()
			for id, session := range s.sessions {
				session.mu.RLock()
				last := session.lastSeen
				session.mu.RUnlock()
				if now.Sub(last) > poolSessionTimeout {
					delete(s.sessions, id)
					expired = append(expired, session)
				}
			}
			s.mu.Unlock()
			for _, session := range expired {
				session.SetConnected(false)
				_ = session.BaseTransport.Stop()
				session.mu.RLock()
				announced := session.announced
				session.mu.RUnlock()
				if announced && s.onRemove != nil {
					s.onRemove(session.clientID)
				}
			}
		}
	}
}

func (p *PoolSession) ClientID() string { return p.clientID }

func (p *PoolSession) Send(data []byte) error {
	if err := p.server.sendData(p, data); err != nil {
		return err
	}
	return nil
}

func (p *PoolSession) Receive(callback func([]byte)) { p.BaseTransport.Receive(callback) }

func (p *PoolSession) IsConnected() bool {
	p.mu.RLock()
	active, docID, last := p.active, p.docID, p.lastSeen
	p.mu.RUnlock()
	if !active || time.Since(last) > poolSessionTimeout {
		return false
	}
	p.server.mu.RLock()
	raw := p.server.docs[docID]
	p.server.mu.RUnlock()
	return raw != nil && raw.IsConnected()
}

func (p *PoolSession) Stop() error {
	p.SetConnected(false)
	return p.BaseTransport.Stop()
}

func (p *PoolSession) Stats() transport.TransportStats { return p.BaseTransport.Stats() }

func effectivePoolVersion(cfg PoolConfig) byte {
	if cfg.ProtocolVersion == 0 {
		return poolProtocolCurrent
	}
	return cfg.ProtocolVersion
}
