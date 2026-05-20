package dto

import (
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
)

type MovieResponse struct {
	ID          string             `json:"id"`
	Title       string             `json:"title"`
	Genre       []string           `json:"genre"`
	Rating      float64            `json:"rating"`
	PosterURL   string             `json:"poster_url"`
	Description string             `json:"description"`
	DurationMin int                `json:"duration_min"`
	Showtimes   []ShowtimeResponse `json:"showtimes,omitempty"`
}

type ShowtimeResponse struct {
	ID          string    `json:"id"`
	MovieID     string    `json:"movie_id"`
	Hall        string    `json:"hall"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Rows        int       `json:"rows"`
	SeatsPerRow int       `json:"seats_per_row"`
	TotalSeats  int       `json:"total_seats"`
	PriceCents  int64     `json:"price_cents"`
	Currency    string    `json:"currency"`
}

func ToMovieResponse(m movie.Movie) MovieResponse {
	showtimes := make([]ShowtimeResponse, len(m.Showtimes))
	for i, st := range m.Showtimes {
		showtimes[i] = ToShowtimeResponse(st)
	}
	return MovieResponse{
		ID:          m.ID,
		Title:       m.Title,
		Genre:       m.Genre,
		Rating:      m.Rating,
		PosterURL:   m.PosterURL,
		Description: m.Description,
		DurationMin: m.DurationMin,
		Showtimes:   showtimes,
	}
}

func ToShowtimeResponse(st movie.Showtime) ShowtimeResponse {
	return ShowtimeResponse{
		ID:          st.ID,
		MovieID:     st.MovieID,
		Hall:        st.Hall,
		StartTime:   st.StartTime,
		EndTime:     st.EndTime,
		Rows:        st.Rows,
		SeatsPerRow: st.SeatsPerRow,
		TotalSeats:  st.Rows * st.SeatsPerRow,
		PriceCents:  st.Price.Cents(),
		Currency:    st.Price.Currency(),
	}
}
