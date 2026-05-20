package booking

import "context"

// Repository persists confirmed/released bookings (MongoDB).
type Repository interface {
	Save(ctx context.Context, b Booking) error
	Update(ctx context.Context, b Booking) error
	FindByID(ctx context.Context, id string) (Booking, error)
	FindBySessionID(ctx context.Context, sessionID string) (Booking, error)
	FindByUserID(ctx context.Context, userID string) ([]Booking, error)
	FindByShowtime(ctx context.Context, showtimeID string) ([]Booking, error)
}

// SeatLockRepository manages short-lived seat locks and session state in Redis.
type SeatLockRepository interface {
	// HoldSeats atomically locks all requested seats and creates a session.
	// Returns ErrSeatAlreadyHeld if any seat is taken.
	HoldSeats(ctx context.Context, req HoldRequest) (Session, error)

	// GetSession retrieves session details by ID.
	GetSession(ctx context.Context, sessionID string) (Session, error)

	// ConfirmSession removes TTLs, making locks permanent until manual cleanup.
	ConfirmSession(ctx context.Context, sessionID string) error

	// ReleaseSession deletes all seat locks and the session key.
	ReleaseSession(ctx context.Context, sessionID string) error

	// GetSeatStatuses returns real-time seat availability for a showtime.
	// requestingUserID is used to mark which seats the caller holds (HeldByMe=true).
	GetSeatStatuses(ctx context.Context, showtimeID string, requestingUserID string) ([]SeatStatus, error)
}

// HoldRequest carries everything needed to hold multiple seats atomically.
type HoldRequest struct {
	SessionID  string
	UserID     string
	ShowtimeID string
	MovieID    string
	SeatIDs    []string
	HoldTTL    int // seconds
}

// Session is the ephemeral booking state stored in Redis during the hold window.
type Session struct {
	ID         string   `json:"id"`
	UserID     string   `json:"user_id"`
	ShowtimeID string   `json:"showtime_id"`
	MovieID    string   `json:"movie_id"`
	SeatIDs    []string `json:"seat_ids"`
	Status     Status   `json:"status"`
	ExpiresAt  int64    `json:"expires_at"` // unix timestamp
}
