package show

import "time"

type ShowStatus string

const (
	ShowStatusScheduled ShowStatus = "scheduled"
	ShowStatusCancelled ShowStatus = "cancelled"
)

// Show is the aggregate root for the show scheduling bounded context.
//
// NOTE — Show vs Showtime: Show (this package) is the admin scheduling layer
// introduced in Milestone D. It references a Theater Screen and tracks
// scheduling conflicts. domain/movie.Showtime is the legacy booking-flow entity
// (hall string, seat grid). The two are currently decoupled; a future milestone
// will bridge Show → Showtime so that admin-scheduled shows drive the public
// booking flow.
type Show struct {
	ID        string
	MovieID   string
	ScreenID  string
	StartTime time.Time
	EndTime   time.Time
	Status    ShowStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Cancel transitions the show to cancelled state.
func (s *Show) Cancel() error {
	if s.Status == ShowStatusCancelled {
		return ErrShowCancelled
	}
	s.Status = ShowStatusCancelled
	s.UpdatedAt = time.Now().UTC()
	return nil
}

// Overlaps returns true if this show's time range overlaps [start, end).
func (s Show) Overlaps(start, end time.Time) bool {
	return s.StartTime.Before(end) && start.Before(s.EndTime)
}
