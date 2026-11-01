package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSessionWithDialerProxiesEveryConnection(t *testing.T) {
	manager := NewSSHManager(39200, 39260, time.Hour, time.Hour)
	t.Cleanup(manager.Shutdown)

	var dials atomic.Int32
	session, err := manager.CreateSessionWithDialer("alice", "lab", "n1", "admin",
		func(context.Context) (net.Conn, error) {
			dials.Add(1)
			client, server := net.Pipe()
			go func() {
				defer func() { _ = server.Close() }()
				_, _ = io.Copy(server, server)
			}()
			return client, nil
		}, time.Hour)
	require.NoError(t, err)

	for range 2 {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", session.Port))
		require.NoError(t, err)
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		buffer := make([]byte, 4)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(conn, buffer)
		require.NoError(t, err)
		require.Equal(t, "ping", string(buffer))
		require.NoError(t, conn.Close())
	}
	require.Equal(t, int32(2), dials.Load(), "every client gets its own connection to the node")

	sessions := manager.ListSessions("alice", false)
	require.Len(t, sessions, 1)
	require.Empty(t, manager.ListSessions("bob", false))

	require.NoError(t, manager.TerminateSession(session.Port))
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", session.Port), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	}, 3*time.Second, 50*time.Millisecond, "the proxy port closes with the session")
}

func TestSessionWithFailingDialerClosesTheClient(t *testing.T) {
	manager := NewSSHManager(39270, 39290, time.Hour, time.Hour)
	t.Cleanup(manager.Shutdown)
	session, err := manager.CreateSessionWithDialer("alice", "lab", "n1", "admin",
		func(context.Context) (net.Conn, error) { return nil, fmt.Errorf("forbidden") }, time.Hour)
	require.NoError(t, err)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", session.Port))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}
