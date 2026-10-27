// tests_go/c9s_capture_suite_test.go
package tests_go

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// pcapngSummary is what the capture tests check in a pcapng stream.
type pcapngSummary struct {
	interfaces []string       // if_name of each Interface Description Block, in order
	packets    map[string]int // Enhanced Packet Blocks per interface name
	icmp       map[string]int // IPv4 ICMP packets per interface name
}

// readPCAPNG parses a little-endian pcapng stream with one section, as containerlab writes it.
func readPCAPNG(data []byte) (pcapngSummary, error) {
	summary := pcapngSummary{packets: map[string]int{}, icmp: map[string]int{}}
	le := binary.LittleEndian
	for offset := 0; offset < len(data); {
		if len(data)-offset < 12 {
			return summary, fmt.Errorf("truncated block at %d", offset)
		}
		blockType := le.Uint32(data[offset:])
		length := int(le.Uint32(data[offset+4:]))
		if length < 12 || offset+length > len(data) {
			return summary, fmt.Errorf("bad block length %d at %d", length, offset)
		}
		body := data[offset+8 : offset+length-4]
		switch blockType {
		case 0x0A0D0D0A:
			if offset != 0 {
				return summary, errors.New("a second section header")
			}
			if le.Uint32(body) != 0x1A2B3C4D {
				return summary, errors.New("not a little-endian section")
			}
		case 1: // Interface Description Block
			name := ""
			for options := body[8:]; len(options) >= 4; {
				code, size := le.Uint16(options), int(le.Uint16(options[2:]))
				if code == 0 || 4+size > len(options) {
					break
				}
				if code == 2 {
					name = string(options[4 : 4+size])
				}
				options = options[4+(size+3)/4*4:]
			}
			summary.interfaces = append(summary.interfaces, name)
		case 6: // Enhanced Packet Block
			id := int(le.Uint32(body))
			if id >= len(summary.interfaces) {
				return summary, fmt.Errorf("packet of undescribed interface %d", id)
			}
			name := summary.interfaces[id]
			captured := int(le.Uint32(body[12:]))
			frame := body[20 : 20+captured]
			summary.packets[name]++
			if len(frame) > 23 && frame[12] == 0x08 && frame[13] == 0x00 && frame[23] == 1 {
				summary.icmp[name]++
			}
		default:
			if offset == 0 {
				return summary, errors.New("the stream does not start with a section header")
			}
		}
		offset += length
	}
	return summary, nil
}

// execInLab runs a command in one node of the capture lab.
func (s *C9sSuite) execInLab(lab, node, command string) {
	s.T().Helper()
	data, status := s.request(http.MethodPost, s.url("/api/v1/labs/%s/exec?nodeFilter=%s", lab, node), s.userHeaders,
		map[string]string{"command": command}, 2*time.Minute)
	s.Require().Equal(http.StatusOK, status, string(data))
	s.Require().Contains(string(data), `"return-code":0`, string(data))
}

// pingInBackground pings n2 from n1 over the link while a capture runs.
func (s *C9sSuite) pingInBackground(lab string, count int) func() {
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _, _ = s.doRequest(http.MethodPost, s.url("/api/v1/labs/%s/exec?nodeFilter=n1", lab), s.userHeaders,
			bytes.NewReader(s.mustMarshal(map[string]string{"command": fmt.Sprintf("ping -c %d -i 0.25 10.98.0.2", count)})), 2*time.Minute)
	})
	return wg.Wait
}

// clabwireCaptures lists the packet-capture processes in the clabwire container of a node's pod.
// A process of a Kubernetes exec is not visible through the API, so it reads /proc on the KinD
// worker that runs the pod (read only). ok is false when the worker is not a KinD node.
func (s *C9sSuite) clabwireCaptures(namespace, node string) (string, bool) {
	s.T().Helper()
	pod, err := s.kubectl("-n", namespace, "get", "pod", "-l", "c9s.run/topologyNode="+node, "-o", "jsonpath={.items[0].metadata.name}")
	s.Require().NoError(err, pod)
	worker, err := s.kubectl("-n", namespace, "get", "pod", pod, "-o", "jsonpath={.spec.nodeName}")
	s.Require().NoError(err, worker)
	container, err := s.kubectl("-n", namespace, "get", "pod", pod, "-o",
		`jsonpath={.status.initContainerStatuses[?(@.name=="clabwire")].containerID}{.status.containerStatuses[?(@.name=="clabwire")].containerID}`)
	s.Require().NoError(err, container)
	_, container, _ = strings.Cut(container, "://")
	if exec.Command("docker", "inspect", "--type", "container", worker).Run() != nil {
		return "", false
	}
	script := fmt.Sprintf(`for proc in /proc/[0-9]*; do if grep -qs '%s' "$proc/cgroup"; then tr '\0' ' ' < "$proc/cmdline" 2>/dev/null; echo; fi; done`, container)
	output, err := exec.Command("docker", "exec", worker, "sh", "-c", script).Output()
	s.Require().NoError(err)
	var captures []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "packet-capture") {
			captures = append(captures, strings.TrimSpace(line))
		}
	}
	return strings.Join(captures, "\n"), true
}

// dialPacketflix connects like cshargextcap does for a packetflix: URL (nif/packetflix.go and
// csharg's host client): it strips "packetflix:" and a trailing /capture, dials <path>/capture
// with the container and nif query parameters and the Clustershark headers, no subprotocol and
// no bearer token. The server's certificate is not verified (--insecure).
func dialPacketflix(packetflixURI string) (*websocket.Conn, *http.Response, error) {
	parsed, err := url.Parse(strings.TrimPrefix(packetflixURI, "packetflix:"))
	if err != nil {
		return nil, nil, err
	}
	container := parsed.Query().Get("container")
	var target struct {
		NetworkInterfaces []string `json:"network-interfaces"`
	}
	if err := json.Unmarshal([]byte(container), &target); err != nil {
		return nil, nil, fmt.Errorf("container parameter: %w", err)
	}
	nif := strings.Join(target.NetworkInterfaces, "/")
	parsed.Path = path.Join(strings.TrimSuffix(parsed.Path, "/capture"), "capture")
	parsed.RawQuery = url.Values{"container": {container}, "nif": {nif}}.Encode()
	dialer := websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // like cshargextcap --insecure against the test server
	}
	return dialer.Dial(parsed.String(), http.Header{"Clustershark-Container": {container}, "Clustershark-Nif": {nif}})
}

// readPacketflix collects the binary messages until the server closes the websocket.
func (s *C9sSuite) readPacketflix(conn *websocket.Conn, deadline time.Duration) ([]byte, int) {
	s.T().Helper()
	var stream []byte
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError
			s.Require().ErrorAs(err, &closeErr, "the server ends the capture with a close frame")
			return stream, closeErr.Code
		}
		s.Require().Equal(websocket.BinaryMessage, messageType)
		stream = append(stream, data...)
	}
}

func (s *C9sSuite) mintTicket(headers http.Header, lab string, body any) (map[string]any, int) {
	data, status := s.request(http.MethodPost, s.url("/api/v1/labs/%s/capture/tickets", lab), headers, body, 2*time.Minute)
	var response map[string]any
	if status == http.StatusCreated {
		s.Require().NoError(json.Unmarshal(data, &response), string(data))
	}
	return response, status
}

func (s *C9sSuite) TestC9sCapture() {
	lab := s.labName + "-cap"
	namespace := fmt.Sprintf("c9s-%s-%s", s.cfg.APIUserUser, lab)
	topology := strings.ReplaceAll(c9sTopology, "{lab_name}", lab)
	data, status, err := s.createLab(s.userHeaders, lab, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status, string(data))
	defer func() {
		_, _, _ = s.destroyLab(s.userHeaders, lab, true, s.cfg.CleanupTimeout)
	}()
	s.execInLab(lab, "n1", "ip addr add 10.98.0.1/24 dev eth1")
	s.execInLab(lab, "n2", "ip addr add 10.98.0.2/24 dev eth1")
	twoTargets := []map[string]string{{"node": "n1", "interface": "eth1"}, {"node": "n2", "interface": "eth1"}}

	s.Run("health advertises capture-stream", func() {
		data, status := s.request(http.MethodGet, s.url("/health"), nil, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status)
		s.Require().Contains(string(data), `"capture-stream"`)
	})

	s.Run("capturable interfaces with their peers", func() {
		data, status := s.request(http.MethodGet, s.url("/api/v1/labs/%s/capture/interfaces", lab), s.userHeaders, nil, 2*time.Minute)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().JSONEq(`[
			{"node":"n1","interface":"eth1","peerNode":"n2","peerInterface":"eth1"},
			{"node":"n2","interface":"eth1","peerNode":"n1","peerInterface":"eth1"}]`, string(data))
	})

	s.Run("stream a 5 s capture of both ends of the link", func() {
		wait := s.pingInBackground(lab, 30)
		defer wait()
		started := time.Now()
		data, status := s.request(http.MethodGet, s.url("/api/v1/labs/%s/capture/stream?target=n1:eth1&target=n2:eth1&duration=5s&download=1", lab),
			s.userHeaders, nil, 2*time.Minute)
		elapsed := time.Since(started)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().GreaterOrEqual(elapsed, 5*time.Second)
		s.Require().Less(elapsed, 40*time.Second)
		summary, err := readPCAPNG(data)
		s.Require().NoError(err)
		s.Require().Equal([]string{"n1:eth1", "n2:eth1"}, summary.interfaces)
		s.Require().Positive(summary.icmp["n1:eth1"], "ICMP on n1:eth1: %+v", summary)
		s.Require().Positive(summary.icmp["n2:eth1"], "ICMP on n2:eth1: %+v", summary)
	})

	s.Run("a client that goes away stops the capture in the pods", func() {
		ctx, cancel := context.WithCancel(context.Background())
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url("/api/v1/labs/%s/capture/stream?target=n1:eth1&target=n2:eth1", lab), nil)
		s.Require().NoError(err)
		request.Header = s.userHeaders.Clone()
		response, err := http.DefaultClient.Do(request)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, response.StatusCode)
		header := make([]byte, 28)
		_, err = io.ReadFull(response.Body, header)
		s.Require().NoError(err, "the section header arrives at once")
		running, ok := s.clabwireCaptures(namespace, "n1")
		if !ok {
			cancel()
			_ = response.Body.Close()
			s.T().Skip("the lab's workers are not KinD nodes; cannot see clabwire processes")
		}
		s.Require().Contains(running, "--stop-on-stdin-close")
		cancel()
		_ = response.Body.Close()
		s.Require().Eventually(func() bool {
			n1, _ := s.clabwireCaptures(namespace, "n1")
			n2, _ := s.clabwireCaptures(namespace, "n2")
			return n1 == "" && n2 == ""
		}, 5*time.Second, 250*time.Millisecond, "no packet-capture process is left in the pods")
	})

	s.Run("a ticket opens a Packetflix websocket once", func() {
		ticket, status := s.mintTicket(s.userHeaders, lab, map[string]any{"targets": twoTargets, "duration": "4s"})
		s.Require().Equal(http.StatusCreated, status)
		uri, _ := ticket["packetflixUri"].(string)
		s.Require().True(strings.HasPrefix(uri, "packetflix:wss://") || strings.HasPrefix(uri, "packetflix:ws://"), uri)

		wait := s.pingInBackground(lab, 24)
		defer wait()
		conn, _, err := dialPacketflix(uri)
		s.Require().NoError(err)
		stream, code := s.readPacketflix(conn, time.Minute)
		_ = conn.Close()
		s.Require().Equal(websocket.CloseNormalClosure, code)
		summary, err := readPCAPNG(stream)
		s.Require().NoError(err)
		s.Require().Equal([]string{"n1:eth1", "n2:eth1"}, summary.interfaces)
		s.Require().Positive(summary.icmp["n1:eth1"], "%+v", summary)
		s.Require().Positive(summary.icmp["n2:eth1"], "%+v", summary)

		_, response, err := dialPacketflix(uri)
		s.Require().ErrorIs(err, websocket.ErrBadHandshake, "a used ticket is refused")
		s.Require().Equal(http.StatusNotFound, response.StatusCode)
	})

	s.Run("an expired ticket is refused", func() {
		ticket, status := s.mintTicket(s.userHeaders, lab, map[string]any{"targets": twoTargets[:1]})
		s.Require().Equal(http.StatusCreated, status)
		expiresAt, err := time.Parse(time.RFC3339Nano, ticket["expiresAt"].(string))
		s.Require().NoError(err)
		s.Require().WithinDuration(time.Now().Add(60*time.Second), expiresAt, 10*time.Second)
		time.Sleep(time.Until(expiresAt) + time.Second)
		_, response, err := dialPacketflix(ticket["packetflixUri"].(string))
		s.Require().ErrorIs(err, websocket.ErrBadHandshake)
		s.Require().Equal(http.StatusNotFound, response.StatusCode)
	})

	s.Run("another user is refused", func() {
		for _, target := range []string{
			s.url("/api/v1/labs/%s/capture/interfaces", lab),
			s.url("/api/v1/labs/%s/capture/stream?target=n1:eth1&duration=1s", lab),
		} {
			data, status := s.request(http.MethodGet, target, s.otherHeaders, nil, s.cfg.RequestTimeout)
			s.Require().Equal(http.StatusNotFound, status, "%s: %s", target, string(data))
		}
		_, status := s.mintTicket(s.otherHeaders, lab, map[string]any{"targets": twoTargets})
		s.Require().Equal(http.StatusNotFound, status)
	})

	s.Run("Wireshark VNC captures through a ticket", func() {
		data, status := s.request(http.MethodGet, s.url("/health"), nil, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status)
		if !strings.Contains(string(data), `"wireshark-vnc"`) {
			s.T().Skip("the server host has no Docker for Wireshark VNC")
		}
		data, status = s.request(http.MethodPost, s.url("/api/v1/labs/%s/capture/wireshark-vnc-sessions", lab), s.userHeaders,
			map[string]any{"targets": []map[string]string{{"containerName": lab + "-n1", "interfaceName": "eth1"}}}, 3*time.Minute)
		s.Require().Equal(http.StatusOK, status, string(data))
		var created struct {
			Sessions []struct{ SessionID string } `json:"sessions"`
		}
		s.Require().NoError(json.Unmarshal(data, &created))
		s.Require().Len(created.Sessions, 1)
		sessionID := created.Sessions[0].SessionID
		defer func() {
			_, _ = s.request(http.MethodDelete, s.url("/api/v1/capture/wireshark-vnc-sessions/%s", sessionID), s.userHeaders, nil, time.Minute)
		}()
		s.Require().Eventually(func() bool {
			data, status := s.request(http.MethodGet, s.url("/api/v1/capture/wireshark-vnc-sessions/%s/ready", sessionID), s.userHeaders, nil, s.cfg.RequestTimeout)
			return status == http.StatusOK && strings.Contains(string(data), `"ready":true`)
		}, 2*time.Minute, 2*time.Second, "the noVNC page answers")
		s.Require().Eventually(func() bool {
			running, ok := s.clabwireCaptures(namespace, "n1")
			return !ok || running != ""
		}, time.Minute, time.Second, "the session's Wireshark redeemed its ticket and the capture runs in the pod")
		data, status = s.request(http.MethodDelete, s.url("/api/v1/capture/wireshark-vnc-sessions/%s", sessionID), s.userHeaders, nil, time.Minute)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().Eventually(func() bool {
			running, _ := s.clabwireCaptures(namespace, "n1")
			return running == ""
		}, 15*time.Second, 500*time.Millisecond, "closing the session stops the capture")
	})
}
