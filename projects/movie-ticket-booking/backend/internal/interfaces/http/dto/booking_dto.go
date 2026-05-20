package dto

import (
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
)

// HoldSeatsRequest is the request body for POST /showtimes/:id/hold.
type HoldSeatsRequest struct {
	UserID  string   `json:"user_id"  binding:"required"`
	SeatIDs []string `json:"seat_ids" binding:"required,min=1,max=4"`
}

// HoldSeatsResponse is returned after a successful hold.
type HoldSeatsResponse struct {
	SessionID  string   `json:"session_id"`
	ShowtimeID string   `json:"showtime_id"`
	MovieID    string   `json:"movie_id"`
	SeatIDs    []string `json:"seat_ids"`
	Status     string   `json:"status"`
	ExpiresAt  int64    `json:"expires_at"` // unix timestamp
}

// ConfirmRequest is the request body for PUT /sessions/:id/confirm.
type ConfirmRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// BookingResponse represents a confirmed booking.
type BookingResponse struct {
	ID          string     `json:"id"`
	SessionID   string     `json:"session_id"`
	UserID      string     `json:"user_id"`
	ShowtimeID  string     `json:"showtime_id"`
	MovieID     string     `json:"movie_id"`
	Seats       []SeatDTO  `json:"seats"`
	Status      string     `json:"status"`
	TotalCents  int64      `json:"total_cents"`
	Currency    string     `json:"currency"`
	CreatedAt   time.Time  `json:"created_at"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

type SeatDTO struct {
	ID     string `json:"id"`
	Row    string `json:"row"`
	Number int    `json:"number"`
}

// SeatStatusResponse is the real-time seat map for a showtime.
type SeatStatusResponse struct {
	SeatID    string `json:"seat_id"`
	Status    string `json:"status"`
	HeldByMe  bool   `json:"held_by_me"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

func ToBookingResponse(b booking.Booking) BookingResponse {
	seats := make([]SeatDTO, len(b.Seats))
	for i, s := range b.Seats {
		seats[i] = SeatDTO{ID: s.ID, Row: s.Row, Number: s.Number}
	}
	return BookingResponse{
		ID:          b.ID,
		SessionID:   b.SessionID,
		UserID:      b.UserID,
		ShowtimeID:  b.ShowtimeID,
		MovieID:     b.MovieID,
		Seats:       seats,
		Status:      string(b.Status),
		TotalCents:  b.TotalPrice.Cents(),
		Currency:    b.TotalPrice.Currency(),
		CreatedAt:   b.CreatedAt,
		ConfirmedAt: b.ConfirmedAt,
	}
}

func ToSeatStatusResponse(s booking.SeatStatus, requestingUserID string, seatSessionMap map[string]string) SeatStatusResponse {
	resp := SeatStatusResponse{
		SeatID:    s.SeatID,
		Status:    s.Status,
		ExpiresAt: s.ExpiresAt,
	}
	if sessionID, ok := seatSessionMap[s.SeatID]; ok {
		resp.HeldByMe = sessionID == requestingUserID
	}
	return resp
}
