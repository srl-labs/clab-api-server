package capture

import (
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testGrant() TicketGrant {
	return TicketGrant{
		Username: "alice",
		LabName:  "lab1",
		Targets:  []Target{{Node: "n1", Interface: "eth1"}, {Node: "n2", Interface: "eth1"}},
		Duration: 5 * time.Second,
	}
}

func TestTicketRedeemsOnceWithItsGrant(t *testing.T) {
	store := NewTicketStore(time.Minute)
	ticket, err := store.Mint(testGrant())
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(ticket.ID)
	require.NoError(t, err)
	require.Len(t, raw, 32, "256 random bits")
	require.WithinDuration(t, time.Now().Add(time.Minute), ticket.ExpiresAt, time.Second)

	grant, err := store.Redeem(ticket.ID, nil)
	require.NoError(t, err)
	require.Equal(t, testGrant(), grant.TicketGrant, "the ticket is bound to the user, the lab and the targets")
	require.Nil(t, grant.Revoked, "nothing revokes a single-use ticket")

	_, err = store.Redeem(ticket.ID, nil)
	require.ErrorIs(t, err, ErrTicketInvalid, "a ticket redeems once")
	require.Zero(t, store.Pending())
}

func TestTicketsAreDistinctAndUnknownOnesFail(t *testing.T) {
	store := NewTicketStore(time.Minute)
	first, err := store.Mint(testGrant())
	require.NoError(t, err)
	second, err := store.Mint(testGrant())
	require.NoError(t, err)
	require.NotEqual(t, first.ID, second.ID)

	for _, id := range []string{"", "nope", first.ID + "x", first.ID[:len(first.ID)-1]} {
		_, err := store.Redeem(id, nil)
		require.ErrorIs(t, err, ErrTicketInvalid, id)
	}
	// Failed redemptions leave the real tickets alone.
	_, err = store.Redeem(first.ID, nil)
	require.NoError(t, err)
	_, err = store.Redeem(second.ID, nil)
	require.NoError(t, err)
}

func TestTicketExpiresSixtySecondsAfterMint(t *testing.T) {
	store := NewTicketStore(0)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	ticket, err := store.Mint(testGrant())
	require.NoError(t, err)
	require.Equal(t, now.Add(60*time.Second), ticket.ExpiresAt, "the default lifetime is 60 s")
	late, err := store.Mint(testGrant())
	require.NoError(t, err)

	now = now.Add(59 * time.Second)
	_, err = store.Redeem(ticket.ID, nil)
	require.NoError(t, err, "valid until the 60 s are over")

	now = now.Add(time.Second)
	_, err = store.Redeem(late.ID, nil)
	require.ErrorIs(t, err, ErrTicketInvalid, "expired at 60 s")
	require.Zero(t, store.Pending(), "an expired ticket is dropped when it is presented")

	expired, err := store.Mint(testGrant())
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	_, err = store.Mint(testGrant())
	require.NoError(t, err)
	require.Equal(t, 1, store.Pending(), "minting sweeps expired tickets")
	_, err = store.Redeem(expired.ID, nil)
	require.ErrorIs(t, err, ErrTicketInvalid)
}

func TestTicketRedeemsOnceUnderConcurrency(t *testing.T) {
	store := NewTicketStore(time.Minute)
	ticket, err := store.Mint(testGrant())
	require.NoError(t, err)

	var redeemed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Go(func() {
			<-start
			if _, err := store.Redeem(ticket.ID, nil); err == nil {
				redeemed.Add(1)
			} else {
				require.ErrorIs(t, err, ErrTicketInvalid)
			}
		})
	}
	close(start)
	wg.Wait()
	require.Equal(t, int32(1), redeemed.Load())
}

func TestTicketGrantIsCopied(t *testing.T) {
	store := NewTicketStore(time.Minute)
	grant := testGrant()
	ticket, err := store.Mint(grant)
	require.NoError(t, err)
	grant.Targets[0].Node = "changed"

	redeemed, err := store.Redeem(ticket.ID, nil)
	require.NoError(t, err)
	require.Equal(t, "n1", redeemed.Targets[0].Node)
}

func TestTicketNeedsUserLabAndTargets(t *testing.T) {
	store := NewTicketStore(time.Minute)
	for _, grant := range []TicketGrant{
		{LabName: "lab1", Targets: testGrant().Targets},
		{Username: "alice", Targets: testGrant().Targets},
		{Username: "alice", LabName: "lab1"},
	} {
		_, err := store.Mint(grant)
		require.Error(t, err)
	}
	require.Zero(t, store.Pending())
}

func TestSessionTicketRedeemsUntilRevoked(t *testing.T) {
	store := NewTicketStore(time.Minute)
	expiresAt := time.Now().Add(2 * time.Hour)
	ticket, err := store.MintSession(testGrant(), expiresAt)
	require.NoError(t, err)
	require.Equal(t, expiresAt, ticket.ExpiresAt, "it lives as long as its session")
	raw, err := base64.RawURLEncoding.DecodeString(ticket.ID)
	require.NoError(t, err)
	require.Len(t, raw, 32)

	// The session's Wireshark restarts its capture: the ticket redeems again, also
	// concurrently, with the same grant.
	first, err := store.Redeem(ticket.ID, nil)
	require.NoError(t, err)
	require.Equal(t, testGrant(), first.TicketGrant)
	require.NotNil(t, first.Revoked)
	var redeemed atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if redemption, err := store.Redeem(ticket.ID, nil); err == nil && redemption.Revoked == first.Revoked {
				redeemed.Add(1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(16), redeemed.Load())
	select {
	case <-first.Revoked:
		t.Fatal("revoked while its session runs")
	default:
	}

	store.Revoke(ticket.ID)
	_, err = store.Redeem(ticket.ID, nil)
	require.ErrorIs(t, err, ErrTicketInvalid, "a closed session's ticket is refused")
	select {
	case <-first.Revoked:
	default:
		t.Fatal("captures on the ticket are not told it was revoked")
	}
	require.Zero(t, store.Pending())
	store.Revoke(ticket.ID) // revoking twice is harmless
	store.Revoke("unknown")
}

func TestSessionTicketExpiresWithItsSession(t *testing.T) {
	store := NewTicketStore(0)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	ticket, err := store.MintSession(testGrant(), now.Add(2*time.Hour))
	require.NoError(t, err)
	now = now.Add(2*time.Hour - time.Second)
	redemption, err := store.Redeem(ticket.ID, nil)
	require.NoError(t, err, "valid long after a single-use ticket's 60 s")
	now = now.Add(time.Second)
	_, err = store.Redeem(ticket.ID, nil)
	require.ErrorIs(t, err, ErrTicketInvalid, "refused once its session expired")
	select {
	case <-redemption.Revoked:
	default:
		t.Fatal("an expired session ticket ends its captures")
	}

	swept, err := store.MintSession(testGrant(), now.Add(time.Minute))
	require.NoError(t, err)
	running, err := store.Redeem(swept.ID, nil)
	require.NoError(t, err)
	now = now.Add(time.Minute)
	_, err = store.Mint(testGrant())
	require.NoError(t, err)
	require.Equal(t, 1, store.Pending(), "minting sweeps expired session tickets")
	select {
	case <-running.Revoked:
	default:
		t.Fatal("a swept session ticket ends its captures")
	}

	_, err = store.MintSession(testGrant(), now)
	require.Error(t, err, "a session that already ended")
	_, err = store.MintSession(testGrant(), time.Time{})
	require.Error(t, err, "a session ticket needs its end")
	_, err = store.MintSession(TicketGrant{Username: "alice", LabName: "lab1"}, now.Add(time.Hour))
	require.Error(t, err, "and targets")
}

func TestTicketIsNeverAcceptedForOtherTargets(t *testing.T) {
	store := NewTicketStore(time.Minute)
	other := func(TicketGrant) ([]Target, error) {
		return nil, fmt.Errorf("%w: n3:eth1", ErrTicketTargets)
	}
	only := func(names ...string) TargetSelector {
		return func(grant TicketGrant) ([]Target, error) { return SelectTargets(grant, names) }
	}

	session, err := store.MintSession(testGrant(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	_, err = store.Redeem(session.ID, other)
	require.ErrorIs(t, err, ErrTicketTargets)
	_, err = store.Redeem(session.ID, only("n1:eth1", "n9:eth1"))
	require.ErrorIs(t, err, ErrTicketTargets, "one target the ticket does not grant refuses the capture")
	redemption, err := store.Redeem(session.ID, only("n2:eth1"))
	require.NoError(t, err, "a refused request leaves the session ticket valid")
	require.Equal(t, []Target{{Node: "n2", Interface: "eth1"}}, redemption.Targets, "a part of the grant")
	redemption, err = store.Redeem(session.ID, only("n2:eth1", "n1:eth1"))
	require.NoError(t, err)
	require.Equal(t, testGrant().Targets, redemption.Targets, "in the grant's order")

	single, err := store.Mint(testGrant())
	require.NoError(t, err)
	_, err = store.Redeem(single.ID, other)
	require.ErrorIs(t, err, ErrTicketTargets)
	_, err = store.Redeem(single.ID, nil)
	require.ErrorIs(t, err, ErrTicketInvalid, "a refused redemption uses up a single-use ticket")
}
