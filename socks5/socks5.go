package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"openflux/utils"
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: addr, dialer: dialer}
}

// Bind reserves the listen address so callers can detect "address already in
// use" synchronously, before serving. Safe to call once; Start binds lazily if
// it wasn't called.
func (s *SOCKS5Server) Bind() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

func (s *SOCKS5Server) Start() error {
	if err := s.Bind(); err != nil {
		return err
	}

	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	defer listener.Close()

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				utils.Debugf("[SOCKS5] Listener closed, stopping")
				return net.ErrClosed
			}
			utils.Debugf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// Close stops the server, unblocking Start's accept loop.
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	if err := negotiateNoAuth(clientConn); err != nil {
		utils.Debugf("[SOCKS5] handshake: %v", err)
		return
	}
	targetAddr, err := readConnectRequest(clientConn)
	if err != nil {
		status := byte(0x01)
		if err == errCommandNotSupported {
			status = 0x07
		} else if err == errAddressNotSupported {
			status = 0x08
		}
		_ = writeReply(clientConn, status)
		utils.Debugf("[SOCKS5] bad request: %v", err)
		return
	}

	utils.Debugf("[SOCKS5] CONNECT %s", targetAddr)
	targetConn, err := s.dialer.DialTCP(targetAddr)
	if err != nil {
		_ = writeReply(clientConn, 0x04)
		utils.Debugf("[SOCKS5] dial failed: %v", err)
		return
	}
	defer targetConn.Close()

	if err := writeReply(clientConn, 0x00); err != nil {
		return
	}
	relay(clientConn, targetConn)
}

func negotiateNoAuth(conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != 0x05 || head[1] == 0 {
		return fmt.Errorf("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0x00 {
			_, err := conn.Write([]byte{0x05, 0x00})
			return err
		}
	}
	_, _ = conn.Write([]byte{0x05, 0xff})
	return fmt.Errorf("client does not offer no-auth method")
}

var (
	errCommandNotSupported = fmt.Errorf("SOCKS5 command is not CONNECT")
	errAddressNotSupported = fmt.Errorf("SOCKS5 address type is unsupported")
)

func readConnectRequest(r io.Reader) (string, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", err
	}
	if head[0] != 0x05 || head[2] != 0 {
		return "", fmt.Errorf("invalid SOCKS5 request header")
	}
	if head[1] != 0x01 {
		return "", errCommandNotSupported
	}

	var host string
	switch head[3] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return "", fmt.Errorf("empty SOCKS5 domain")
		}
		domain := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", errAddressNotSupported
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return "", fmt.Errorf("SOCKS5 destination port is zero")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func writeReply(w io.Writer, status byte) error {
	_, err := w.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

type closeWriter interface {
	CloseWrite() error
}

func relay(client, target net.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(target, client)
		if cw, ok := target.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(client, target)
	if cw, ok := client.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	<-done
}
