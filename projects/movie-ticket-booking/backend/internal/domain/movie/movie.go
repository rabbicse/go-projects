package movie

import (
	"errors"
	"strings"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

// Movie is the aggregate root for the movie catalog bounded context.
type Movie struct {
	ID          string
	Title       string
	Genre       []string
	Rating      float64
	PosterURL   string
	Description string
	DurationMin int
	Showtimes   []Showtime
	Published   bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Showtime is an entity belonging to the Movie aggregate.
type Showtime struct {
	ID          string
	MovieID     string
	Hall        string
	StartTime   time.Time
	EndTime     time.Time
	Rows        int
	SeatsPerRow int
	Price       shared.Money
}

// Publish marks the movie as publicly visible. Returns ValidationError if invariants fail.
func (m *Movie) Publish() error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.Published = true
	m.UpdatedAt = time.Now().UTC()
	return nil
}

// Unpublish removes the movie from public listing.
func (m *Movie) Unpublish() {
	m.Published = false
	m.UpdatedAt = time.Now().UTC()
}

// Validate checks domain invariants without changing state.
func (m *Movie) Validate() error {
	var msgs []string
	if strings.TrimSpace(m.Title) == "" {
		msgs = append(msgs, "title is required")
	}
	if len(m.Genre) == 0 {
		msgs = append(msgs, "at least one genre is required")
	}
	if m.DurationMin < 1 {
		msgs = append(msgs, "duration must be at least 1 minute")
	}
	if m.Rating < 0 || m.Rating > 10 {
		msgs = append(msgs, "rating must be between 0 and 10")
	}
	if len(msgs) > 0 {
		return &ValidationError{Messages: msgs}
	}
	return nil
}

func (m *Movie) AddShowtime(s Showtime) error {
	if s.MovieID != m.ID {
		return errors.New("showtime does not belong to this movie")
	}
	for _, existing := range m.Showtimes {
		if existing.Hall == s.Hall && timesOverlap(existing.StartTime, existing.EndTime, s.StartTime, s.EndTime) {
			return errors.New("showtime conflicts with an existing showtime in the same hall")
		}
	}
	m.Showtimes = append(m.Showtimes, s)
	return nil
}

func (m *Movie) TotalSeats() int {
	total := 0
	for _, st := range m.Showtimes {
		total += st.Rows * st.SeatsPerRow
	}
	return total
}

func timesOverlap(s1, e1, s2, e2 time.Time) bool {
	return s1.Before(e2) && s2.Before(e1)
}
