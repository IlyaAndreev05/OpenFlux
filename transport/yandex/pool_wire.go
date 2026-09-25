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
	poolProtocolLegacy  = 1
	poolProtocolCurrent = 2
	poolProtocolVersion = poolProtocolCurrent
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
	Version   byte
	Kind      byte
	Direction byte
	ClientID  string
	SessionID [16]byte
	Epoch     uint64
	Challenge [16]byte
	DocID     string
	Payload   []byte
}

func encodePoolFrame(f poolFrame) ([]byte, error) {
	if len(f.ClientID) == 0 || len(f.ClientID) > 64 || len(f.DocID) > 64 || len(f.Payload) > poolMaxFrameBytes {
		return nil, errors.New("invalid pool frame field length")
	}
	version := f.Version
	if version == 0 {
		version = poolProtocolVersion
	}
	fixed := 37
	if version == poolProtocolCurrent {
		fixed += 16
	} else if version != poolProtocolLegacy {
		return nil, fmt.Errorf("unsupported pool protocol version %d", version)
	}
	total := fixed + len(f.ClientID) + len(f.DocID) + len(f.Payload)
	if total > poolMaxFrameBytes {
		return nil, errors.New("pool frame exceeds maximum size")
	}
	out := make([]byte, total)
	copy(out[:4], "OFP1")
	out[4] = version
	out[5] = f.Kind
	out[6] = f.Direction
	out[7] = byte(len(f.ClientID))
	out[8] = byte(len(f.DocID))
	copy(out[9:25], f.SessionID[:])
	binary.BigEndian.PutUint64(out[25:33], f.Epoch)
	binary.BigEndian.PutUint32(out[33:37], uint32(len(f.Payload)))
	if version == poolProtocolCurrent {
		copy(out[37:53], f.Challenge[:])
	}
	copy(out[fixed:], f.ClientID)
	copy(out[fixed+len(f.ClientID):], f.DocID)
	copy(out[fixed+len(f.ClientID)+len(f.DocID):], f.Payload)
	return out, nil
}

func decodePoolFrame(data []byte) (poolFrame, error) {
	if len(data) < 37 || len(data) > poolMaxFrameBytes || string(data[:4]) != "OFP1" {
		return poolFrame{}, errors.New("invalid pool frame header")
	}
	version := data[4]
	fixed := 37
	if version == poolProtocolCurrent {
		fixed += 16
	} else if version != poolProtocolLegacy {
		return poolFrame{}, errors.New("invalid pool frame version")
	}
	if len(data) < fixed {
		return poolFrame{}, errors.New("truncated pool frame")
	}
	idLen, docLen := int(data[7]), int(data[8])
	payloadLen := int(binary.BigEndian.Uint32(data[33:37]))
	if idLen == 0 || idLen > 64 || docLen > 64 || payloadLen > poolMaxFrameBytes ||
		len(data) != fixed+idLen+docLen+payloadLen {
		return poolFrame{}, errors.New("invalid pool frame length")
	}
	f := poolFrame{
		Version: version, Kind: data[5], Direction: data[6],
		ClientID: string(data[fixed : fixed+idLen]),
		Epoch:    binary.BigEndian.Uint64(data[25:33]),
	}
	copy(f.SessionID[:], data[9:25])
	if version == poolProtocolCurrent {
		copy(f.Challenge[:], data[37:53])
	}
	docStart := fixed + idLen
	f.DocID = string(data[docStart : docStart+docLen])
	f.Payload = append([]byte(nil), data[docStart+docLen:]...)
	return f, nil
}

func normalizedPoolVersion(version byte) byte {
	if version == 0 {
		return poolProtocolVersion
	}
	return version
}

func poolMACInput(context string, f poolFrame) []byte {
	version := normalizedPoolVersion(f.Version)
	prefix := "OpenFlux Yandex pool v2\x00"
	if version == poolProtocolLegacy {
		prefix = "OpenFlux Yandex pool v1\x00"
	}
	out := make([]byte, 0, len(prefix)+len(context)+160)
	out = append(out, []byte(prefix)...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(context)))
	out = append(out, n[:]...)
	out = append(out, context...)
	out = append(out, version, f.Kind, f.Direction)
	var idLen [2]byte
	binary.BigEndian.PutUint16(idLen[:], uint16(len(f.ClientID)))
	out = append(out, idLen[:]...)
	out = append(out, f.ClientID...)
	out = append(out, f.SessionID[:]...)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], f.Epoch)
	out = append(out, u[:]...)
	binary.BigEndian.PutUint16(idLen[:], uint16(len(f.DocID)))
	out = append(out, idLen[:]...)
	out = append(out, f.DocID...)
	if version == poolProtocolCurrent {
		out = append(out, f.Challenge[:]...)
	}
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
	version  byte
	mu       sync.Mutex
	txSeq    uint64
	rxHigh   uint64
	rxReady  bool
	seenSeq  map[uint64]struct{}
	seen     map[string]struct{}
	seenFIFO []string
}

// newPoolCipher constructs a protocol-v2 cipher. Protocol v1 is available
// only through newPoolCipherVersion for explicit migrations.
func newPoolCipher(key [32]byte, context, clientID string, server bool) (*poolCipher, error) {
	return newPoolCipherVersion(key, context, clientID, server, poolProtocolCurrent)
}

func newPoolCipherVersion(key [32]byte, context, clientID string, server bool, version byte) (*poolCipher, error) {
	return newPoolSessionCipher(key, context, clientID, server, version, [16]byte{}, 0)
}

func newPoolSessionCipher(key [32]byte, context, clientID string, server bool, version byte, sessionID [16]byte, epoch uint64) (*poolCipher, error) {
	if version != poolProtocolLegacy && version != poolProtocolCurrent {
		return nil, fmt.Errorf("unsupported pool protocol version %d", version)
	}
	master := key
	if version == poolProtocolCurrent && (sessionID != [16]byte{} || epoch != 0) {
		m := hmac.New(sha256.New, key[:])
		_, _ = m.Write([]byte("OpenFlux Yandex pool session v2\x00"))
		writePoolString(m, context)
		writePoolString(m, clientID)
		_, _ = m.Write(sessionID[:])
		var e [8]byte
		binary.BigEndian.PutUint64(e[:], epoch)
		_, _ = m.Write(e[:])
		copy(master[:], m.Sum(nil))
	}
	c2s := derivePoolKey(master, context, clientID, "client-to-exit", version)
	s2c := derivePoolKey(master, context, clientID, "exit-to-client", version)
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
	return &poolCipher{
		tx: tx, rx: rx, txDir: txDir, rxDir: rxDir, version: version,
		seenSeq: make(map[uint64]struct{}), seen: make(map[string]struct{}),
	}, nil
}

type poolHashWriter interface{ Write([]byte) (int, error) }

func writePoolString(w poolHashWriter, value string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value)))
	_, _ = w.Write(n[:])
	_, _ = w.Write([]byte(value))
}

func derivePoolKey(key [32]byte, context, clientID, direction string, version byte) [32]byte {
	m := hmac.New(sha256.New, key[:])
	if version == poolProtocolLegacy {
		_, _ = m.Write([]byte("OpenFlux Yandex pool key v1\x00"))
		_, _ = m.Write([]byte(context))
		_, _ = m.Write([]byte{0})
		_, _ = m.Write([]byte(clientID))
		_, _ = m.Write([]byte{0})
		_, _ = m.Write([]byte(direction))
	} else {
		_, _ = m.Write([]byte("OpenFlux Yandex pool key v2\x00"))
		writePoolString(m, context)
		writePoolString(m, clientID)
		writePoolString(m, direction)
	}
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (c *poolCipher) seal(f poolFrame, plaintext []byte) (poolFrame, error) {
	f.Payload = nil
	f.Version = c.version
	nonce := make([]byte, c.tx.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return poolFrame{}, fmt.Errorf("make pool nonce: %w", err)
	}
	f.Direction = c.txDir
	cleartext := plaintext
	if c.version == poolProtocolCurrent {
		c.mu.Lock()
		if c.txSeq == ^uint64(0) {
			c.mu.Unlock()
			return poolFrame{}, errors.New("pool sequence exhausted")
		}
		c.txSeq++
		seq := c.txSeq
		c.mu.Unlock()
		cleartext = make([]byte, 8+len(plaintext))
		binary.BigEndian.PutUint64(cleartext[:8], seq)
		copy(cleartext[8:], plaintext)
	}
	aad := poolMACInput("", f)
	payload := make([]byte, 0, len(nonce)+len(cleartext)+c.tx.Overhead())
	payload = append(payload, nonce...)
	payload = c.tx.Seal(payload, nonce, cleartext, aad)
	f.Payload = payload
	return f, nil
}

func (c *poolCipher) open(f poolFrame) ([]byte, error) {
	if f.Version != c.version || f.Direction != c.rxDir || len(f.Payload) < c.rx.NonceSize()+c.rx.Overhead() {
		return nil, errors.New("invalid encrypted pool frame")
	}
	nonce := f.Payload[:c.rx.NonceSize()]
	aad := poolMACInput("", f)
	plain, err := c.rx.Open(nil, nonce, f.Payload[c.rx.NonceSize():], aad)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version == poolProtocolCurrent {
		if len(plain) < 8 {
			return nil, errors.New("encrypted pool frame has no sequence")
		}
		seq := binary.BigEndian.Uint64(plain[:8])
		if seq == 0 || (c.rxReady && seq <= c.rxHigh && c.rxHigh-seq >= poolReplayLimit) {
			return nil, errors.New("pool sequence outside replay window")
		}
		if _, ok := c.seenSeq[seq]; ok {
			return nil, errors.New("replayed pool frame")
		}
		c.seenSeq[seq] = struct{}{}
		if !c.rxReady || seq > c.rxHigh {
			c.rxHigh = seq
			c.rxReady = true
			floor := uint64(1)
			if c.rxHigh >= poolReplayLimit {
				floor = c.rxHigh - poolReplayLimit + 1
			}
			for old := range c.seenSeq {
				if old < floor {
					delete(c.seenSeq, old)
				}
			}
		}
		return append([]byte(nil), plain[8:]...), nil
	}
	key := string(nonce)
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
	if cfg.ProtocolVersion == poolProtocolCurrent || cfg.ProtocolVersion == 0 {
		// Document endpoints are mutable routing data, not pool identity.
		b.WriteString("v2\x00")
		b.WriteString(cfg.PoolID)
		return b.String()
	}
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
