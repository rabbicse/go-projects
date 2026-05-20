package dto

import (
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

type CreateMovieRequest struct {
	ID          string   `json:"id"           binding:"required"`
	Title       string   `json:"title"        binding:"required"`
	Genre       []string `json:"genre"        binding:"required,min=1"`
	Rating      float64  `json:"rating"       binding:"required,min=0,max=10"`
	PosterURL   string   `json:"poster_url"`
	Description string   `json:"description"`
	DurationMin int      `json:"duration_min" binding:"required,min=1"`
}

type CreateShowtimeRequest struct {
	ID          string    `json:"id"           binding:"required"`
	Hall        string    `json:"hall"         binding:"required"`
	StartTime   time.Time `json:"start_time"   binding:"required"`
	EndTime     time.Time `json:"end_time"     binding:"required"`
	Rows        int       `json:"rows"         binding:"required,min=1,max=26"`
	SeatsPerRow int       `json:"seats_per_row" binding:"required,min=1,max=30"`
	PriceCents  int64     `json:"price_cents"  binding:"required,min=0"`
	Currency    string    `json:"currency"     binding:"required"`
}

func (r CreateMovieRequest) ToDomain() movie.Movie {
	return movie.Movie{
		ID:          r.ID,
		Title:       r.Title,
		Genre:       r.Genre,
		Rating:      r.Rating,
		PosterURL:   r.PosterURL,
		Description: r.Description,
		DurationMin: r.DurationMin,
	}
}

func (r CreateShowtimeRequest) ToDomain(movieID string) movie.Showtime {
	return movie.Showtime{
		ID:          r.ID,
		MovieID:     movieID,
		Hall:        r.Hall,
		StartTime:   r.StartTime,
		EndTime:     r.EndTime,
		Rows:        r.Rows,
		SeatsPerRow: r.SeatsPerRow,
		Price:       shared.NewMoney(r.PriceCents, r.Currency),
	}
}
