package movie

import (
	"errors"
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
