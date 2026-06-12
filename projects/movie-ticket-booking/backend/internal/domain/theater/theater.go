package theater

import (
	"strings"
	"time"
)

type TheaterStatus string

const (
	TheaterStatusActive   TheaterStatus = "active"
	TheaterStatusDisabled TheaterStatus = "disabled"
)

type ScreenStatus string

const (
	ScreenStatusActive   ScreenStatus = "active"
	ScreenStatusDisabled ScreenStatus = "disabled"
)

type SeatCategory string

const (
	SeatCategoryStandard SeatCategory = "standard"
	SeatCategoryPremium  SeatCategory = "premium"
	SeatCategoryVIP      SeatCategory = "vip"
)

// Theater is the aggregate root for the theater bounded context.
type Theater struct {
	ID        string
	Name      string
	Location  string
	Status    TheaterStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Screen is an entity belonging to the Theater aggregate.
type Screen struct {
	ID        string
	TheaterID string
	Name      string
	Capacity  int
	Seats     []Seat
	Status    ScreenStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Seat is a value object representing a single seat in a screen.
type Seat struct {
	ID       string
	Row      string
	Number   int
	Category SeatCategory
}

// ValidationError holds a single invariant violation.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

func (t *Theater) Disable() {
	t.Status = TheaterStatusDisabled
	t.UpdatedAt = time.Now().UTC()
}

func (s *Screen) Disable() {
	s.Status = ScreenStatusDisabled
	s.UpdatedAt = time.Now().UTC()
}

func (t *Theater) Validate() error {
	if strings.TrimSpace(t.Name) == "" {
		return &ValidationError{Message: "name is required"}
	}
	return nil
}
