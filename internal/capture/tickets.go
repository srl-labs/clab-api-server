package capture

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// DefaultTicketTTL is how long a capture ticket can be redeemed after it was minted.
const DefaultTicketTTL = 60 * time.Second

// ticketBytes is the ticket's entropy: 256 bits.
const ticketBytes = 32

// ErrTicketInvalid reports a ticket that is unknown, already used or expired. The three cases
// are not told apart, so a caller learns nothing about tickets it does not hold.
var ErrTicketInvalid = errors.New("capture ticket is invalid, used or expired")

// Target is one interface of one node a ticket captures.
type Target struct {
	Node      string
	Interface string
}

// TicketGrant is what a ticket allows: one capture of these targets of this lab, as this
// user.
type TicketGrant struct {
	Username string
	LabName  string
	Targets  []Target
	// Duration ends the capture; zero captures until the client disconnects.
	Duration time.Duration
}

// Ticket is a minted capture ticket.
type Ticket struct {
	// ID is the credential: random, URL safe, single use.
	ID        string
	ExpiresAt time.Time
}

// TicketStore mints and redeems single-use capture tickets. Clients that cannot send a bearer
// token (the packetflix: URL handler, the Wireshark VNC container) present a ticket instead.
// The store keeps only a hash of each ticket.
type TicketStore struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	tickets map[[sha256.Size]byte]storedTicket
}

type storedTicket struct {
	grant     TicketGrant
	expiresAt time.Time
}

// NewTicketStore returns a store whose tickets expire ttl after they were minted.
func NewTicketStore(ttl time.Duration) *TicketStore {
	if ttl <= 0 {
		ttl = DefaultTicketTTL
	}
	return &TicketStore{ttl: ttl, now: time.Now, tickets: map[[sha256.Size]byte]storedTicket{}}
}

// Mint stores a grant and returns the ticket that redeems it.
func (s *TicketStore) Mint(grant TicketGrant) (Ticket, error) {
	if grant.Username == "" || grant.LabName == "" || len(grant.Targets) == 0 {
		return Ticket{}, errors.New("a capture ticket needs a user, a lab and at least one target")
	}
	raw := make([]byte, ticketBytes)
	if _, err := rand.Read(raw); err != nil {
		return Ticket{}, fmt.Errorf("generating a capture ticket: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	grant.Targets = slices.Clone(grant.Targets)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now)
	expiresAt := now.Add(s.ttl)
	s.tickets[sha256.Sum256([]byte(id))] = storedTicket{grant: grant, expiresAt: expiresAt}
	return Ticket{ID: id, ExpiresAt: expiresAt}, nil
}

// Redeem consumes a ticket and returns its grant. A ticket redeems once: concurrent and later
// redemptions, and redemptions after it expired, fail with ErrTicketInvalid.
func (s *TicketStore) Redeem(id string) (TicketGrant, error) {
	if id == "" {
		return TicketGrant{}, ErrTicketInvalid
	}
	key := sha256.Sum256([]byte(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.tickets[key]
	if !ok {
		return TicketGrant{}, ErrTicketInvalid
	}
	delete(s.tickets, key)
	if !s.now().Before(stored.expiresAt) {
		return TicketGrant{}, ErrTicketInvalid
	}
	stored.grant.Targets = slices.Clone(stored.grant.Targets)
	return stored.grant, nil
}

// Pending returns the number of stored tickets, expired ones included until the next sweep.
func (s *TicketStore) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}

func (s *TicketStore) sweepLocked(now time.Time) {
	for key, stored := range s.tickets {
		if !now.Before(stored.expiresAt) {
			delete(s.tickets, key)
		}
	}
}
