package dto

import (
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
)

type CreateShowRequest struct {
	ID        string    `json:"id"         binding:"required"`
	MovieID   string    `json:"movie_id"   binding:"required"`
	ScreenID  string    `json:"screen_id"  binding:"required"`
	StartTime time.Time `json:"start_time" binding:"required"`
	EndTime   time.Time `json:"end_time"   binding:"required"`
}

type UpdateShowRequest struct {
	MovieID   string    `json:"movie_id"   binding:"required"`
	ScreenID  string    `json:"screen_id"  binding:"required"`
	StartTime time.Time `json:"start_time" binding:"required"`
	EndTime   time.Time `json:"end_time"   binding:"required"`
}

type ShowResponse struct {
	ID        string `json:"id"`
	MovieID   string `json:"movie_id"`
	ScreenID  string `json:"screen_id"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (r CreateShowRequest) ToDomain() show.Show {
	now := time.Now().UTC()
	return show.Show{
		ID:        r.ID,
		MovieID:   r.MovieID,
		ScreenID:  r.ScreenID,
		StartTime: r.StartTime,
		EndTime:   r.EndTime,
		Status:    show.ShowStatusScheduled,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func ToShowResponse(s show.Show) ShowResponse {
	return ShowResponse{
		ID:        s.ID,
		MovieID:   s.MovieID,
		ScreenID:  s.ScreenID,
		StartTime: s.StartTime.Format(time.RFC3339),
		EndTime:   s.EndTime.Format(time.RFC3339),
		Status:    string(s.Status),
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		UpdatedAt: s.UpdatedAt.Format(time.RFC3339),
	}
}
