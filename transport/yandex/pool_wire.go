package yandex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"
	"sync"
)

const (
	poolProtocolVersion = 1
	poolMaxFrameBytes   = 128 << 10
	poolReplayLimit     = 1024
)

const (
	poolHello byte = iota + 1
	poolAssign
	poolBind
	poolReady
	poolData
	poolPing
	poolPong
	poolClose
)

type poolFrame struct {
	Kind      byte
	Direction byte
	ClientID  string
	SessionID [16]byte
	Epoch     uint64
	DocID     string
	Payload   []byte
}

func encodePoolFrame(f poolFrame) ([]byte, error) {
	if len(f.ClientID) == 0 || len(f.ClientID) > 64 || len(f.DocID) > 64 || len(f.Payload) > poolMaxFrameBytes {
		return nil, errors.New("invalid pool frame field length")
	}
	total := 37 + len(f.ClientID) + len(f.DocID) + len(f.Payload)
	if total > poolMaxFrameBytes {
		return nil, errors.New("pool frame exceeds maximum size")
	}
	out := make([]byte, total)
	copy(out[:4], "OFP1")
	out[4] = poolProtocolVersion
	out[5] = f.Kind
	out[6] = f.Direction
	out[7] = byte(len(f.ClientID))
	out[8] = byte(len(f.DocID))
	copy(out[9:25], f.SessionID[:])
	binary.BigEndian.PutUint64(out[25:33], f.Epoch)
	binary.BigEndian.PutUint32(out[33:37], uint32(len(f.Payload)))
	copy(out[37:], f.ClientID)
	copy(out[37+len(f.ClientID):], f.DocID)
	copy(out[37+len(f.ClientID)+len(f.DocID):], f.Payload)
	return out, nil
}

func decodePoolFrame(data []byte) (poolFrame, error) {
	if len(data) < 37 || len(data) > poolMaxFrameBytes || string(data[:4]) != "OFP1" || data[4] != poolProtocolVersion {
		return poolFrame{}, errors.New("invalid pool frame header")
	}
	idLen, docLen := int(data[7]), int(data[8])
	payloadLen := int(binary.BigEndian.Uint32(data[33:37]))
	if idLen == 0 || idLen > 64 || docLen > 64 || payloadLen > poolMaxFrameBytes ||
		len(data) != 37+idLen+docLen+payloadLen {
		return poolFrame{}, errors.New("invalid pool frame length")
	}
	f := poolFrame{
		Kind: data[5], Direction: data[6],
		ClientID: string(data[37 : 37+idLen]),
		Epoch:    binary.BigEndian.Uint64(data[25:33]),
	}
	copy(f.SessionID[:], data[9:25])
	docStart := 37 + idLen
	f.DocID = string(data[docStart : docStart+docLen])
	f.Payload = append([]byte(nil), data[docStart+docLen:]...)
	return f, nil
}

func poolMACInput(context string, f poolFrame) []byte {
	// Length prefixes prevent IDs or URLs from creating ambiguous contexts.
	out := make([]byte, 0, len(context)+128)
	out = append(out, []byte("OpenFlux Yandex pool v1\x00")...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(context)))
	out = append(out, n[:]...)
	out = append(out, context...)
	out = append(out, poolProtocolVersion, f.Kind, f.Direction)
	var idLen [2]byte
	binary.BigEndian.PutUint16(idLen[:], uint16(len(f.ClientID)))
	out = append(out, idLen[:]...)
	out = append(out, f.ClientID...)
	out = append(out, f.SessionID[:]...)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], f.Epoch)
	out = append(out, u[:]...)
	binary.BigEndian.PutUint16(n[:], uint16(len(f.DocID)))
	out = append(out, n[:]...)
	out = append(out, f.DocID...)
	return out
}

func poolProof(key [32]byte, context string, f poolFrame) []byte {
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write(poolMACInput(context, f))
	return m.Sum(nil)
}

func verifyPoolProof(key [32]byte, context string, f poolFrame) bool {
	want := poolProof(key, context, f)
	return len(f.Payload) == len(want) && subtle.ConstantTimeCompare(f.Payload, want) == 1
}

type poolCipher struct {
	tx       cipher.AEAD
	rx       cipher.AEAD
	txDir    byte
	rxDir    byte
	mu       sync.Mutex
	seen     map[string]struct{}
	seenFIFO []string
}

func newPoolCipher(key [32]byte, context, clientID string, server bool) (*poolCipher, error) {
	c2s := derivePoolKey(key, context, clientID, "client-to-exit")
	s2c := derivePoolKey(key, context, clientID, "exit-to-client")
	txKey, rxKey := c2s, s2c
	txDir, rxDir := byte(0), byte(1)
	if server {
		txKey, rxKey = s2c, c2s
		txDir, rxDir = 1, 0
	}
	txBlock, err := aes.NewCipher(txKey[:])
	if err != nil {
		return nil, err
	}
	tx, err := cipher.NewGCM(txBlock)
	if err != nil {
		return nil, err
	}
	rxBlock, err := aes.NewCipher(rxKey[:])
	if err != nil {
		return nil, err
	}
	rx, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return nil, err
	}
	return &poolCipher{tx: tx, rx: rx, txDir: txDir, rxDir: rxDir, seen: make(map[string]struct{})}, nil
}

func derivePoolKey(key [32]byte, context, clientID, direction string) [32]byte {
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write([]byte("OpenFlux Yandex pool key v1\x00"))
	_, _ = m.Write([]byte(context))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(clientID))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(direction))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (c *poolCipher) seal(f poolFrame, plaintext []byte) (poolFrame, error) {
	f.Payload = nil
	nonce := make([]byte, c.tx.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return poolFrame{}, fmt.Errorf("make pool nonce: %w", err)
	}
	f.Direction = c.txDir
	aad := poolMACInput("", f)
	payload := make([]byte, 0, len(nonce)+len(plaintext)+c.tx.Overhead())
	payload = append(payload, nonce...)
	payload = c.tx.Seal(payload, nonce, plaintext, aad)
	f.Payload = payload
	return f, nil
}

func (c *poolCipher) open(f poolFrame) ([]byte, error) {
	if f.Direction != c.rxDir || len(f.Payload) < c.rx.NonceSize()+c.rx.Overhead() {
		return nil, errors.New("invalid encrypted pool frame")
	}
	nonce := f.Payload[:c.rx.NonceSize()]
	aad := poolMACInput("", f)
	plain, err := c.rx.Open(nil, nonce, f.Payload[c.rx.NonceSize():], aad)
	if err != nil {
		return nil, err
	}
	key := string(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return nil, errors.New("replayed pool frame")
	}
	c.seen[key] = struct{}{}
	c.seenFIFO = append(c.seenFIFO, key)
	if len(c.seenFIFO) > poolReplayLimit {
		old := c.seenFIFO[0]
		c.seenFIFO = c.seenFIFO[1:]
		delete(c.seen, old)
	}
	return plain, nil
}

func poolDomain(cfg PoolConfig) string {
	docs := append([]PoolDocument(nil), cfg.Docs...)
	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })
	var b strings.Builder
	b.WriteString(cfg.PoolID)
	for _, d := range docs {
		b.WriteByte(0)
		b.WriteString(d.ID)
		b.WriteByte(0)
		b.WriteString(d.URL)
	}
	return b.String()
}

func stickyIndex(clientID string, docs []PoolDocument) int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(clientID))
	return int(h.Sum64() % uint64(len(docs)))
}
