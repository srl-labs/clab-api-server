package capture

import (
	"encoding/base64"
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

	grant, err := store.Redeem(ticket.ID)
	require.NoError(t, err)
	require.Equal(t, testGrant(), grant, "the ticket is bound to the user, the lab and the targets")

	_, err = store.Redeem(ticket.ID)
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
		_, err := store.Redeem(id)
		require.ErrorIs(t, err, ErrTicketInvalid, id)
	}
	// Failed redemptions leave the real tickets alone.
	_, err = store.Redeem(first.ID)
	require.NoError(t, err)
	_, err = store.Redeem(second.ID)
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
	_, err = store.Redeem(ticket.ID)
	require.NoError(t, err, "valid until the 60 s are over")

	now = now.Add(time.Second)
	_, err = store.Redeem(late.ID)
	require.ErrorIs(t, err, ErrTicketInvalid, "expired at 60 s")
	require.Zero(t, store.Pending(), "an expired ticket is dropped when it is presented")

	expired, err := store.Mint(testGrant())
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	_, err = store.Mint(testGrant())
	require.NoError(t, err)
	require.Equal(t, 1, store.Pending(), "minting sweeps expired tickets")
	_, err = store.Redeem(expired.ID)
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
			if _, err := store.Redeem(ticket.ID); err == nil {
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

	redeemed, err := store.Redeem(ticket.ID)
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
