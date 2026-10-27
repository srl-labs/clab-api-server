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

// ErrTicketInvalid reports a ticket that is unknown, already used, revoked or expired. The
// cases are not told apart, so a caller learns nothing about tickets it does not hold.
var ErrTicketInvalid = errors.New("capture ticket is invalid, used or expired")

// ErrTicketTargets reports a redemption for targets the ticket does not grant.
var ErrTicketTargets = errors.New("capture ticket does not grant these targets")

// Target is one interface of one node a ticket captures.
type Target struct {
	Node      string
	Interface string
}

// TicketGrant is what a ticket allows: captures of these targets of this lab, as this user.
type TicketGrant struct {
	Username string
	LabName  string
	Targets  []Target
	// Duration ends the capture; zero captures until the client disconnects.
	Duration time.Duration
}

// Ticket is a minted capture ticket.
type Ticket struct {
	// ID is the credential: random and URL safe.
	ID        string
	ExpiresAt time.Time
}

// Redemption is a redeemed ticket: the capture it allows.
type Redemption struct {
	// TicketGrant is the grant, with the targets of this capture.
	TicketGrant
	// Revoked is closed when a session ticket is revoked or found expired, so captures that
	// run on it end with the session. It is nil for a single-use ticket.
	Revoked <-chan struct{}
}

// TargetSelector picks the targets of one capture from a ticket's grant. It refuses targets
// the grant does not name with an error that wraps ErrTicketTargets.
type TargetSelector func(TicketGrant) ([]Target, error)

// TicketStore mints and redeems capture tickets. Clients that cannot send a bearer token (the
// packetflix: URL handler, the Wireshark VNC container) present a ticket instead. The store
// keeps only a hash of each ticket.
//
// There are two kinds:
//   - a single-use ticket (Mint) redeems once, and expires ttl after it was minted;
//   - a session ticket (MintSession) belongs to a Wireshark VNC session: it redeems any number
//     of times until the session revokes it, or until the session's end, so the session's
//     Wireshark can restart its capture.
type TicketStore struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	tickets map[[sha256.Size]byte]*storedTicket
}

type storedTicket struct {
	grant     TicketGrant
	expiresAt time.Time
	// session tickets redeem until revoked; revoked is closed then.
	session bool
	revoked chan struct{}
}

// NewTicketStore returns a store whose single-use tickets expire ttl after they were minted.
func NewTicketStore(ttl time.Duration) *TicketStore {
	if ttl <= 0 {
		ttl = DefaultTicketTTL
	}
	return &TicketStore{ttl: ttl, now: time.Now, tickets: map[[sha256.Size]byte]*storedTicket{}}
}

// Mint stores a grant and returns the single-use ticket that redeems it.
func (s *TicketStore) Mint(grant TicketGrant) (Ticket, error) {
	return s.mint(grant, time.Time{}, false)
}

// MintSession stores a grant and returns a session ticket that redeems it until Revoke, or
// until expiresAt.
func (s *TicketStore) MintSession(grant TicketGrant, expiresAt time.Time) (Ticket, error) {
	if expiresAt.IsZero() {
		return Ticket{}, errors.New("a session capture ticket needs the end of its session")
	}
	return s.mint(grant, expiresAt, true)
}

func (s *TicketStore) mint(grant TicketGrant, expiresAt time.Time, session bool) (Ticket, error) {
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
	if !session {
		expiresAt = now.Add(s.ttl)
	} else if !now.Before(expiresAt) {
		return Ticket{}, errors.New("the session of this capture ticket has already ended")
	}
	stored := &storedTicket{grant: grant, expiresAt: expiresAt, session: session}
	if session {
		stored.revoked = make(chan struct{})
	}
	s.tickets[sha256.Sum256([]byte(id))] = stored
	return Ticket{ID: id, ExpiresAt: expiresAt}, nil
}

// Redeem redeems a ticket for one capture. selectTargets, when not nil, picks the capture's
// targets from the grant; nil captures all of them.
//
// A single-use ticket redeems once: its first redemption consumes it, also when it is refused,
// and concurrent and later redemptions fail with ErrTicketInvalid. A session ticket redeems
// until it is revoked or expires; a refused redemption leaves it valid. Expired tickets fail
// with ErrTicketInvalid, targets the grant does not name with ErrTicketTargets.
func (s *TicketStore) Redeem(id string, selectTargets TargetSelector) (Redemption, error) {
	if id == "" {
		return Redemption{}, ErrTicketInvalid
	}
	key := sha256.Sum256([]byte(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.tickets[key]
	if !ok {
		return Redemption{}, ErrTicketInvalid
	}
	if !s.now().Before(stored.expiresAt) {
		s.dropLocked(key, stored)
		return Redemption{}, ErrTicketInvalid
	}
	if !stored.session {
		delete(s.tickets, key)
	}
	grant := stored.grant
	grant.Targets = slices.Clone(grant.Targets)
	if selectTargets != nil {
		targets, err := selectTargets(grant)
		if err != nil {
			return Redemption{}, err
		}
		grant.Targets = targets
	}
	redemption := Redemption{TicketGrant: grant}
	if stored.session {
		redemption.Revoked = stored.revoked
	}
	return redemption, nil
}

// Revoke ends a session ticket: it no longer redeems, and the captures that run on it are
// told through their Redemption.Revoked. Unknown tickets are ignored.
func (s *TicketStore) Revoke(id string) {
	key := sha256.Sum256([]byte(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.tickets[key]; ok {
		s.dropLocked(key, stored)
	}
}

// Pending returns the number of stored tickets, expired ones included until the next sweep.
func (s *TicketStore) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}

func (s *TicketStore) dropLocked(key [sha256.Size]byte, stored *storedTicket) {
	delete(s.tickets, key)
	if stored.revoked != nil {
		close(stored.revoked)
	}
}

func (s *TicketStore) sweepLocked(now time.Time) {
	for key, stored := range s.tickets {
		if !now.Before(stored.expiresAt) {
			s.dropLocked(key, stored)
		}
	}
}

// SelectTargets returns the grant's targets that names (as "<node>:<interface>") ask for, in
// the grant's order; no names select all of them. A name the grant does not have is refused.
func SelectTargets(grant TicketGrant, names []string) ([]Target, error) {
	if len(names) == 0 {
		return slices.Clone(grant.Targets), nil
	}
	wanted := make(map[string]bool, len(names))
	granted := make(map[string]bool, len(grant.Targets))
	for _, target := range grant.Targets {
		granted[target.Name()] = true
	}
	for _, name := range names {
		if !granted[name] {
			return nil, fmt.Errorf("%w: %s", ErrTicketTargets, name)
		}
		wanted[name] = true
	}
	selected := make([]Target, 0, len(wanted))
	for _, target := range grant.Targets {
		if wanted[target.Name()] {
			selected = append(selected, target)
		}
	}
	return selected, nil
}

// Name is the target as captures name it: "<node>:<interface>".
func (t Target) Name() string { return t.Node + ":" + t.Interface }
