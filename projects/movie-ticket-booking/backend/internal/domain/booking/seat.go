package booking

import (
	"fmt"
	"strings"
)

// Seat is a value object identifying a physical seat.
type Seat struct {
	ID     string // e.g. "A1", "B3"
	Row    string
	Number int
}

// NewSeat constructs a Seat from a composite ID like "A1".
func NewSeat(id string) (Seat, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if len(id) < 2 {
		return Seat{}, fmt.Errorf("invalid seat id %q", id)
	}
	row := string(id[0])
	if row < "A" || row > "Z" {
		return Seat{}, fmt.Errorf("invalid row in seat id %q", id)
	}
	var num int
	if _, err := fmt.Sscanf(id[1:], "%d", &num); err != nil || num < 1 {
		return Seat{}, fmt.Errorf("invalid number in seat id %q", id)
	}
	return Seat{ID: id, Row: row, Number: num}, nil
}

// SeatStatus describes the real-time state of a seat returned to clients.
type SeatStatus struct {
	SeatID    string `json:"seat_id"`
	Status    string `json:"status"`    // "available" | "held" | "confirmed"
	HeldByMe  bool   `json:"held_by_me"` // true when the requesting user holds this seat
	ExpiresAt *int64 `json:"expires_at,omitempty"` // unix seconds remaining for held seats
}
