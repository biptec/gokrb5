package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		// 1 means we should always use TCP.
		rb, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %v", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		// Try UDP first, TCP second.
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// A KRBError other than RESPONSE_TOO_BIG is a valid KDC response.
				return rb, e
			}
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}

	// Try TCP first, UDP second.
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			return rb, e
		}
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}
	return rb, nil
}

const (
	kdcNetworkTimeout   = 5 * time.Second
	kdcResolutionWindow = 1 * time.Second
	kdcFallbackDelay    = 250 * time.Millisecond
	kdcFallbackWindow   = 1 * time.Second
)

type kdcLookupFunc func(context.Context, string) ([]net.IPAddr, error)

type kdcLookupResult struct {
	index     int
	addresses []string
	err       error
}

type kdcAttemptResult struct {
	address  string
	response []byte
	err      error
}

// normalizeKDCIP converts IPv4-mapped IPv6 addresses to their canonical IPv4
// representation and rejects invalid IP values.
func normalizeKDCIP(address net.IPAddr) (net.IPAddr, bool) {
	if address.IP == nil {
		return net.IPAddr{}, false
	}
	if ip4 := address.IP.To4(); ip4 != nil {
		if address.Zone != "" {
			return net.IPAddr{}, false
		}
		return net.IPAddr{IP: append(net.IP(nil), ip4...)}, true
	}
	if ip6 := address.IP.To16(); ip6 != nil {
		return net.IPAddr{
			IP:   append(net.IP(nil), ip6...),
			Zone: address.Zone,
		}, true
	}
	return net.IPAddr{}, false
}

// parseKDCIP recognizes an IP literal, including a scoped IPv6 literal.
func parseKDCIP(host string) (net.IPAddr, bool) {
	ipHost := host
	zone := ""
	if separator := strings.LastIndex(host, "%"); separator >= 0 {
		ipHost = host[:separator]
		zone = host[separator+1:]
		if zone == "" {
			return net.IPAddr{}, false
		}
	}

	ip := net.ParseIP(ipHost)
	if ip == nil {
		return net.IPAddr{}, false
	}
	return normalizeKDCIP(net.IPAddr{IP: ip, Zone: zone})
}

// splitKDCAddress validates a configured host:port KDC address.
func splitKDCAddress(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("invalid KDC address %q: %w", address, err)
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid KDC address %q: host is empty", address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("invalid KDC port %q in %q", port, address)
	}
	return host, port, nil
}

// resolveKDCAddresses expands each configured KDC hostname into all available
// A and AAAA addresses. Lookups run concurrently, while the returned candidates
// retain the KDC preference order supplied by Config.GetKDCs.
func resolveKDCAddresses(ctx context.Context, kdcs map[int]string, lookup kdcLookupFunc) ([]string, error) {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		}
	}

	indexes := make([]int, 0, len(kdcs))
	for index := range kdcs {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	if len(indexes) == 0 {
		return nil, fmt.Errorf("no KDCs are configured")
	}

	resolutionCtx, cancelResolution := context.WithTimeout(ctx, kdcResolutionWindow)
	defer cancelResolution()

	results := make(chan kdcLookupResult, len(indexes))
	for _, index := range indexes {
		index := index
		go func() {
			host, port, err := splitKDCAddress(kdcs[index])
			if err != nil {
				results <- kdcLookupResult{index: index, err: err}
				return
			}

			var addresses []net.IPAddr
			var lookupErr error
			if ip, ok := parseKDCIP(host); ok {
				addresses = []net.IPAddr{ip}
			} else if strings.Contains(host, "%") {
				results <- kdcLookupResult{
					index: index,
					err:   fmt.Errorf("invalid scoped KDC IP address %q", host),
				}
				return
			} else {
				// Keep any successful family results even if the resolver also
				// reports a partial lookup error for the other address family.
				addresses, lookupErr = lookup(resolutionCtx, host)
			}

			candidates := make([]string, 0, len(addresses))
			for _, address := range addresses {
				normalized, ok := normalizeKDCIP(address)
				if !ok {
					continue
				}
				candidates = append(candidates, net.JoinHostPort(normalized.String(), port))
			}
			if len(candidates) == 0 {
				if lookupErr != nil {
					results <- kdcLookupResult{
						index: index,
						err:   fmt.Errorf("resolve KDC %q: %w", host, lookupErr),
					}
					return
				}
				results <- kdcLookupResult{
					index: index,
					err:   fmt.Errorf("KDC %q has no usable A or AAAA addresses", host),
				}
				return
			}
			results <- kdcLookupResult{index: index, addresses: candidates}
		}()
	}

	byIndex := make(map[int]kdcLookupResult, len(indexes))
	remaining := len(indexes)
	for remaining > 0 {
		select {
		case result := <-results:
			byIndex[result.index] = result
			remaining--
		case <-resolutionCtx.Done():
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("KDC address resolution exceeded its overall deadline: %w", err)
			}
			remaining = 0
		}
	}

	// Include lookups that completed at the resolution-window boundary. A
	// stalled KDC lookup must not hide another KDC whose addresses resolved.
drainResults:
	for {
		select {
		case result := <-results:
			if _, exists := byIndex[result.index]; !exists {
				byIndex[result.index] = result
			}
		default:
			break drainResults
		}
	}

	candidates := make([]string, 0, len(indexes)*2)
	seen := make(map[string]struct{})
	var lookupErrors []string
	for _, index := range indexes {
		result, resolved := byIndex[index]
		if !resolved {
			lookupErrors = append(lookupErrors, fmt.Sprintf("KDC %q resolution exceeded %s window", kdcs[index], kdcResolutionWindow))
			continue
		}
		if result.err != nil {
			lookupErrors = append(lookupErrors, result.err.Error())
			continue
		}
		for _, address := range result.addresses {
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			candidates = append(candidates, address)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("could not resolve any KDC address: %s", strings.Join(lookupErrors, "; "))
	}
	return candidates, nil
}

// raceKDCAddresses starts candidate attempts with a short stagger. The first
// successful KDC response wins; every candidate shares one overall deadline.
func raceKDCAddresses(ctx context.Context, addresses []string, attempt func(context.Context, string) ([]byte, error)) ([]byte, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no resolved KDC addresses")
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan kdcAttemptResult, len(addresses))
	stagger := kdcFallbackDelay
	if len(addresses) > 1 && time.Duration(len(addresses)-1)*stagger > kdcFallbackWindow {
		stagger = kdcFallbackWindow / time.Duration(len(addresses)-1)
	}
	for index, address := range addresses {
		index, address := index, address
		go func() {
			if delay := time.Duration(index) * stagger; delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-attemptCtx.Done():
					return
				case <-timer.C:
				}
			}

			response, err := attempt(attemptCtx, address)
			select {
			case results <- kdcAttemptResult{address: address, response: response, err: err}:
			case <-attemptCtx.Done():
			}
		}()
	}

	var attemptErrors []string
	completed := 0
	for completed < len(addresses) {
		select {
		case result := <-results:
			completed++
			if result.err == nil && len(result.response) > 0 {
				cancel()
				return result.response, nil
			}
			if result.err == nil {
				result.err = fmt.Errorf("empty response")
			}
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", result.address, result.err))
		case <-ctx.Done():
			return nil, fmt.Errorf("KDC address attempts exceeded their overall deadline: %s: %w", strings.Join(attemptErrors, "; "), ctx.Err())
		}
	}
	return nil, fmt.Errorf("all KDC addresses failed: %s", strings.Join(attemptErrors, "; "))
}

func closeConnectionOnContextDone(ctx context.Context, conn net.Conn) func() {
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-finished:
		}
	}()
	return func() { close(finished) }
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var response []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return response, err
	}
	response, err = dialSendUDP(kdcs, b)
	if err != nil {
		return response, err
	}
	return checkForKRBError(response)
}

// dialSendUDP establishes a UDP connection to any configured KDC address.
// A and AAAA candidates are attempted with a staggered fallback and one
// five-second deadline shared by DNS resolution and network attempts.
func dialSendUDP(kdcs map[int]string, b []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kdcNetworkTimeout)
	defer cancel()

	addresses, err := resolveKDCAddresses(ctx, kdcs, nil)
	if err != nil {
		return nil, err
	}
	return raceKDCAddresses(ctx, addresses, func(ctx context.Context, address string) ([]byte, error) {
		return sendUDPToKDC(ctx, address, b)
	})
}

func sendUDPToKDC(ctx context.Context, address string, b []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	stopClose := closeConnectionOnContextDone(ctx, conn)
	defer stopClose()
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set UDP KDC deadline: %w", err)
		}
	}
	if _, err := conn.Write(b); err != nil {
		return nil, fmt.Errorf("send UDP request to %s: %w", address, err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("read UDP response from %s: %w", address, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("no response data from %s", address)
	}
	return response[:n], nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var response []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return response, err
	}
	response, err = dialSendTCP(kdcs, b)
	if err != nil {
		return response, err
	}
	return checkForKRBError(response)
}

// dialSendTCP establishes a TCP connection to any configured KDC address.
// DNS resolution and every candidate share one five-second deadline.
func dialSendTCP(kdcs map[int]string, b []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kdcNetworkTimeout)
	defer cancel()

	addresses, err := resolveKDCAddresses(ctx, kdcs, nil)
	if err != nil {
		return nil, err
	}
	return raceKDCAddresses(ctx, addresses, func(ctx context.Context, address string) ([]byte, error) {
		return sendTCPToKDC(ctx, address, b)
	})
}

func sendTCPToKDC(ctx context.Context, address string, b []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stopClose := closeConnectionOnContextDone(ctx, conn)
	defer stopClose()
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set TCP KDC deadline: %w", err)
		}
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected TCP connection type %T", conn)
	}
	return sendTCP(tcpConn, b)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn *net.TCPConn, b []byte) ([]byte, error) {
	defer conn.Close()
	var response []byte

	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the message length.
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(b)))
	request := append(header, b...)

	if err := writeAll(conn, request); err != nil {
		return response, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr(), err)
	}

	responseHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, responseHeader); err != nil {
		return response, fmt.Errorf("error reading response size header: %w", err)
	}
	responseSize := binary.BigEndian.Uint32(responseHeader)
	if responseSize == 0 {
		return response, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr())
	}
	if uint64(responseSize) > uint64(^uint(0)>>1) {
		return response, fmt.Errorf("KDC response size %d exceeds the platform allocation limit", responseSize)
	}
	response = make([]byte, int(responseSize))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	if len(response) == 0 {
		return response, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr())
	}
	return response, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
