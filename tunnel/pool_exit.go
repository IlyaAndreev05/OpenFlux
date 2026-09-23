package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"openflux/transport"
	"openflux/tunnel/l3"
	"openflux/utils"
)

type PoolExitNode struct {
	mode ExitMode
	mu   sync.RWMutex
	l4   *multiProxyExit
	l3   *l3.MultiClientExit
}

func NewPoolExitNode(mode ExitMode) (*PoolExitNode, error) {
	return NewPoolExitNodeWithForward(mode, "", "")
}

// NewPoolExitNodeWithForward optionally restricts L4 pool traffic to one
// virtual endpoint and forwards it to one loopback service.
func NewPoolExitNodeWithForward(mode ExitMode, virtualEndpoint, target string) (*PoolExitNode, error) {
	var forward *poolL4Forward
	if virtualEndpoint != "" || target != "" {
		if mode != ExitModeL4 {
			return nil, fmt.Errorf("pool forward route requires L4 mode")
		}
		virtual, err := netip.ParseAddrPort(virtualEndpoint)
		if err != nil || !virtual.Addr().Is4() || virtual.Addr().IsLoopback() || virtual.Port() == 0 {
			return nil, fmt.Errorf("invalid pool forward virtual endpoint %q", virtualEndpoint)
		}
		local, err := netip.ParseAddrPort(target)
		if err != nil || !local.Addr().Is4() || !local.Addr().IsLoopback() || local.Port() == 0 {
			return nil, fmt.Errorf("pool forward target must be a loopback IPv4 endpoint, got %q", target)
		}
		forward = &poolL4Forward{virtualEndpoint: virtual, target: local}
	}
	n := &PoolExitNode{mode: mode}
	if mode == ExitModeL3 {
		exit, err := l3.NewMultiClientExit()
		if err != nil {
			return nil, err
		}
		n.l3 = exit
	} else {
		n.l4 = newMultiProxyExit(forward)
	}
	return n, nil
}

func (n *PoolExitNode) Start() error {
	if n.l4 != nil {
		return n.l4.Start()
	}
	return n.l3.Start()
}

func (n *PoolExitNode) AddClient(id string, trans transport.Transport) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.l4 != nil {
		return n.l4.AddClient(id, trans)
	}
	return n.l3.AddClient(id, trans)
}

func (n *PoolExitNode) RemoveClient(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.l4 != nil {
		n.l4.RemoveClient(id)
	} else {
		n.l3.RemoveClient(id)
	}
}

func (n *PoolExitNode) Stop() error {
	if n.l4 != nil {
		return n.l4.Stop()
	}
	return n.l3.Stop()
}

type poolL4Client struct {
	id string
	ip [4]byte
	transport.Transport
}

type poolL4Forward struct {
	virtualEndpoint netip.AddrPort
	target          netip.AddrPort
}

type multiProxyExit struct {
	stack   *stack.Stack
	ep      *TunnelLinkEndpoint
	forward *poolL4Forward

	mu          sync.RWMutex
	clients     map[string]*poolL4Client
	byIP        map[[4]byte]*poolL4Client
	nextIP      atomic.Uint32
	started     atomic.Bool
	startTime   time.Time
	activeFlows atomic.Int64
}

func newMultiProxyExit(forward *poolL4Forward) *multiProxyExit {
	t := &multiProxyExit{
		forward:   forward,
		clients:   make(map[string]*poolL4Client),
		byIP:      make(map[[4]byte]*poolL4Client),
		startTime: time.Now(),
	}
	t.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	setPoolTCPBuffers(t.stack)
	t.ep = NewTunnelLinkEndpoint()
	t.ep.onOutgoingPacket = t.handleFromStack
	if err := t.stack.CreateNIC(1, t.ep); err != nil {
		utils.Debugf("[POOL-L4] CreateNIC: %v", err)
	}
	t.stack.SetPromiscuousMode(1, true)
	t.stack.SetSpoofing(1, true)
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	fwd := tcp.NewForwarder(t.stack, 0, 8192, t.handleExitTCP)
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return t
}

func (t *multiProxyExit) Start() error {
	if !t.started.CompareAndSwap(false, true) {
		return fmt.Errorf("pool L4 exit already started")
	}
	return nil
}

func (t *multiProxyExit) AddClient(id string, trans transport.Transport) error {
	if id == "" || trans == nil {
		return fmt.Errorf("pool L4 client requires id and transport")
	}
	n := t.nextIP.Add(1)
	if n >= 65535 {
		return fmt.Errorf("pool L4 virtual address space exhausted")
	}
	ip := [4]byte{10, 64, byte(n >> 8), byte(n)}
	client := &poolL4Client{id: id, ip: ip, Transport: trans}
	t.mu.Lock()
	if old := t.clients[id]; old != nil {
		delete(t.byIP, old.ip)
		_ = old.Transport.Stop()
	}
	t.clients[id] = client
	t.byIP[ip] = client
	t.mu.Unlock()
	trans.Receive(func(pkt []byte) {
		cp, ok := poolRewriteIPv4Address(pkt, 12, [4]byte{10, 10, 10, 2}, ip)
		if !ok {
			return
		}
		t.ep.InjectInbound(cp)
	})
	return nil
}

func (t *multiProxyExit) RemoveClient(id string) {
	t.mu.Lock()
	client := t.clients[id]
	if client != nil {
		delete(t.clients, id)
		delete(t.byIP, client.ip)
	}
	t.mu.Unlock()
	if client != nil {
		_ = client.Transport.Stop()
	}
}

func (t *multiProxyExit) handleFromStack(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	t.mu.RLock()
	client := t.byIP[dst]
	t.mu.RUnlock()
	if client == nil {
		return
	}
	cp, ok := poolRewriteIPv4Address(pkt, 16, dst, [4]byte{10, 10, 10, 2})
	if !ok {
		return
	}
	if err := client.Transport.Send(cp); err != nil {
		utils.Debugf("[POOL-L4] send to client %s: %v", client.id, err)
	}
}

const maxPoolL4Flows = 65_536

func (t *multiProxyExit) handleExitTCP(r *tcp.ForwarderRequest) {
	if t.activeFlows.Add(1) > maxPoolL4Flows {
		t.activeFlows.Add(-1)
		r.Complete(true)
		utils.Debugf("[POOL-L4] flow limit reached (%d)", maxPoolL4Flows)
		return
	}
	id := r.ID()
	dest := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	resolved, allowed := resolvePoolL4Destination(dest, t.forward)
	if !allowed {
		t.activeFlows.Add(-1)
		r.Complete(true)
		utils.Debugf("[POOL-L4] rejected destination %s outside configured Xray route", dest)
		return
	}
	dest = resolved
	var wq waiter.Queue
	ep, tErr := r.CreateEndpoint(&wq)
	if tErr != nil {
		t.activeFlows.Add(-1)
		utils.Debugf("[POOL-L4] CreateEndpoint %s: %v", dest, tErr)
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	utils.SafeGo("pool-exit.flow", func() {
		defer t.activeFlows.Add(-1)
		remote, err := net.DialTimeout("tcp", dest, 10*time.Second)
		if err != nil {
			utils.Debugf("[POOL-L4] dial %s failed: %v", dest, err)
			local.Close()
			return
		}
		if tc, ok := remote.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetReadBuffer(16 * 1024 * 1024)
			_ = tc.SetWriteBuffer(16 * 1024 * 1024)
		}
		go func() {
			_, _ = io.Copy(remote, local)
			_ = remote.Close()
			_ = local.Close()
		}()
		_, _ = io.Copy(local, remote)
		_ = local.Close()
		_ = remote.Close()
	})
}

func (t *multiProxyExit) Stop() error {
	t.stack.Close()
	t.mu.Lock()
	clients := make([]*poolL4Client, 0, len(t.clients))
	for _, c := range t.clients {
		clients = append(clients, c)
	}
	t.clients = make(map[string]*poolL4Client)
	t.byIP = make(map[[4]byte]*poolL4Client)
	t.mu.Unlock()
	for _, c := range clients {
		_ = c.Transport.Stop()
	}
	return nil
}

// poolRewriteIPv4Address rewrites one IPv4 address and recalculates IPv4 and TCP checksums.
func poolRewriteIPv4Address(pkt []byte, offset int, old, next [4]byte) ([]byte, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || (offset != 12 && offset != 16) {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(pkt[2])<<8 | int(pkt[3])
	if ihl < 20 || total < ihl || total > len(pkt) {
		return nil, false
	}
	if string(pkt[offset:offset+4]) != string(old[:]) {
		return nil, false
	}
	if pkt[9] == 6 {
		fragment := binary.BigEndian.Uint16(pkt[6:8])
		if fragment&0x3fff != 0 || total < ihl+20 {
			return nil, false
		}
		tcpHeaderLen := int(pkt[ihl+12]>>4) * 4
		if tcpHeaderLen < 20 || total < ihl+tcpHeaderLen {
			return nil, false
		}
	}
	cp := append([]byte(nil), pkt[:total]...)
	copy(cp[offset:offset+4], next[:])
	cp[10], cp[11] = 0, 0
	ipSum := tunnelOnesComplement(cp[:ihl])
	cp[10], cp[11] = byte(ipSum>>8), byte(ipSum)
	if cp[9] == 6 && total >= ihl+20 {
		tcpSeg := cp[ihl:]
		tcpSeg[16], tcpSeg[17] = 0, 0
		var src, dst [4]byte
		copy(src[:], cp[12:16])
		copy(dst[:], cp[16:20])
		sum := tunnelTCPChecksum(tcpSeg, src, dst)
		tcpSeg[16], tcpSeg[17] = byte(sum>>8), byte(sum)
	}
	return cp, true
}

func tunnelOnesComplement(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tunnelTCPChecksum(seg []byte, src, dst [4]byte) uint16 {
	var sum uint32
	for _, ip := range [][4]byte{src, dst} {
		sum += uint32(ip[0])<<8 | uint32(ip[1])
		sum += uint32(ip[2])<<8 | uint32(ip[3])
	}
	sum += 6
	sum += uint32(len(seg))
	for i := 0; i+1 < len(seg); i += 2 {
		sum += uint32(seg[i])<<8 | uint32(seg[i+1])
	}
	if len(seg)%2 != 0 {
		sum += uint32(seg[len(seg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func setPoolTCPBuffers(s *stack.Stack) {
	const minBuffer = 64 * 1024
	const defaultBuffer = 256 * 1024
	const maxBuffer = 1024 * 1024
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: minBuffer, Default: defaultBuffer, Max: maxBuffer}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		utils.Debugf("[POOL-L4] set receive buffer: %v", err)
	}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: minBuffer, Default: defaultBuffer, Max: maxBuffer}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		utils.Debugf("[POOL-L4] set send buffer: %v", err)
	}
}

func resolvePoolL4Destination(destination string, forward *poolL4Forward) (string, bool) {
	if forward == nil {
		return destination, true
	}
	requested, err := netip.ParseAddrPort(destination)
	if err != nil || requested != forward.virtualEndpoint {
		return "", false
	}
	return forward.target.String(), true
}
