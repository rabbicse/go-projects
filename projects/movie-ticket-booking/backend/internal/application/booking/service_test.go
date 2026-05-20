package booking_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

// --- Mocks ---

type mockSeatLock struct{ mock.Mock }

func (m *mockSeatLock) HoldSeats(ctx context.Context, req booking.HoldRequest) (booking.Session, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(booking.Session), args.Error(1)
}
func (m *mockSeatLock) GetSession(ctx context.Context, sessionID string) (booking.Session, error) {
	args := m.Called(ctx, sessionID)
	return args.Get(0).(booking.Session), args.Error(1)
}
func (m *mockSeatLock) ConfirmSession(ctx context.Context, sessionID string) error {
	return m.Called(ctx, sessionID).Error(0)
}
func (m *mockSeatLock) ReleaseSession(ctx context.Context, sessionID string) error {
	return m.Called(ctx, sessionID).Error(0)
}
func (m *mockSeatLock) GetSeatStatuses(ctx context.Context, showtimeID string, userID string) ([]booking.SeatStatus, error) {
	args := m.Called(ctx, showtimeID, userID)
	return args.Get(0).([]booking.SeatStatus), args.Error(1)
}

type mockBookingRepo struct{ mock.Mock }

func (m *mockBookingRepo) Save(ctx context.Context, b booking.Booking) error {
	return m.Called(ctx, b).Error(0)
}
func (m *mockBookingRepo) Update(ctx context.Context, b booking.Booking) error {
	return m.Called(ctx, mock.AnythingOfType("booking.Booking")).Error(0)
}
func (m *mockBookingRepo) FindByID(ctx context.Context, id string) (booking.Booking, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(booking.Booking), args.Error(1)
}
func (m *mockBookingRepo) FindBySessionID(ctx context.Context, sessionID string) (booking.Booking, error) {
	args := m.Called(ctx, sessionID)
	return args.Get(0).(booking.Booking), args.Error(1)
}
func (m *mockBookingRepo) FindByUserID(ctx context.Context, userID string) ([]booking.Booking, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]booking.Booking), args.Error(1)
}
func (m *mockBookingRepo) FindByShowtime(ctx context.Context, showtimeID string) ([]booking.Booking, error) {
	args := m.Called(ctx, showtimeID)
	return args.Get(0).([]booking.Booking), args.Error(1)
}

type mockMovieRepo struct{ mock.Mock }

func (m *mockMovieRepo) FindAll(ctx context.Context) ([]movie.Movie, error) {
	args := m.Called(ctx)
	return args.Get(0).([]movie.Movie), args.Error(1)
}
func (m *mockMovieRepo) FindByID(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}
func (m *mockMovieRepo) FindShowtime(ctx context.Context, id string) (movie.Showtime, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Showtime), args.Error(1)
}
func (m *mockMovieRepo) Save(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockMovieRepo) SaveShowtime(ctx context.Context, s movie.Showtime) error {
	return m.Called(ctx, s).Error(0)
}
func (m *mockMovieRepo) UpsertMany(ctx context.Context, movies []movie.Movie) error {
	return m.Called(ctx, movies).Error(0)
}

// --- Helpers ---

func newService(sl *mockSeatLock, br *mockBookingRepo, mr *mockMovieRepo) *bookingsvc.Service {
	return bookingsvc.NewService(sl, br, mr, 4, 10*time.Minute)
}

func sampleShowtime() movie.Showtime {
	return movie.Showtime{
		ID: "show-1", MovieID: "movie-1", Hall: "A",
		StartTime: time.Now().Add(time.Hour), EndTime: time.Now().Add(3 * time.Hour),
		Rows: 8, SeatsPerRow: 10, Price: shared.USD(1500),
	}
}

// --- Tests ---

func TestHoldSeats_Success(t *testing.T) {
	sl := &mockSeatLock{}
	br := &mockBookingRepo{}
	mr := &mockMovieRepo{}
	svc := newService(sl, br, mr)

	showtime := sampleShowtime()
	sessionID := uuid.New().String()
	session := booking.Session{
		ID: sessionID, UserID: "u1", ShowtimeID: "show-1", MovieID: "movie-1",
		SeatIDs: []string{"A1", "A2"}, Status: booking.StatusHeld,
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}

	mr.On("FindShowtime", mock.Anything, "show-1").Return(showtime, nil)
	sl.On("HoldSeats", mock.Anything, mock.AnythingOfType("booking.HoldRequest")).Return(session, nil)
	br.On("Save", mock.Anything, mock.AnythingOfType("booking.Booking")).Return(nil)

	got, err := svc.HoldSeats(context.Background(), "u1", "show-1", []string{"A1", "A2"})
	require.NoError(t, err)
	assert.Equal(t, []string{"A1", "A2"}, got.SeatIDs)
	sl.AssertExpectations(t)
}

func TestHoldSeats_ExceedsMax(t *testing.T) {
	svc := newService(&mockSeatLock{}, &mockBookingRepo{}, &mockMovieRepo{})
	_, err := svc.HoldSeats(context.Background(), "u1", "show-1", []string{"A1", "A2", "A3", "A4", "A5"})
	assert.ErrorIs(t, err, booking.ErrMaxSeatsExceeded)
}

func TestHoldSeats_SeatAlreadyHeld(t *testing.T) {
	sl := &mockSeatLock{}
	br := &mockBookingRepo{}
	mr := &mockMovieRepo{}
	svc := newService(sl, br, mr)

	mr.On("FindShowtime", mock.Anything, "show-1").Return(sampleShowtime(), nil)
	sl.On("HoldSeats", mock.Anything, mock.AnythingOfType("booking.HoldRequest")).
		Return(booking.Session{}, booking.ErrSeatAlreadyHeld)

	_, err := svc.HoldSeats(context.Background(), "u1", "show-1", []string{"A1"})
	assert.ErrorIs(t, err, booking.ErrSeatAlreadyHeld)
}

func TestConfirmBooking_Success(t *testing.T) {
	sl := &mockSeatLock{}
	br := &mockBookingRepo{}
	mr := &mockMovieRepo{}
	svc := newService(sl, br, mr)

	seats := []booking.Seat{{ID: "A1", Row: "A", Number: 1}}
	b, _ := booking.New("session-1", "u1", "show-1", "movie-1", seats, shared.USD(1500), 10*time.Minute)
	b.ID = "booking-1"

	sl.On("GetSession", mock.Anything, "session-1").Return(booking.Session{
		ID: "session-1", UserID: "u1", ShowtimeID: "show-1", SeatIDs: []string{"A1"},
	}, nil)
	br.On("FindBySessionID", mock.Anything, "session-1").Return(b, nil)
	sl.On("ConfirmSession", mock.Anything, "session-1").Return(nil)
	br.On("Update", mock.Anything, mock.AnythingOfType("booking.Booking")).Return(nil)

	confirmed, err := svc.ConfirmBooking(context.Background(), "session-1", "u1")
	require.NoError(t, err)
	assert.Equal(t, booking.StatusConfirmed, confirmed.Status)
}

func TestConfirmBooking_WrongUser(t *testing.T) {
	sl := &mockSeatLock{}
	svc := newService(sl, &mockBookingRepo{}, &mockMovieRepo{})

	sl.On("GetSession", mock.Anything, "session-1").Return(booking.Session{
		ID: "session-1", UserID: "other-user",
	}, nil)

	_, err := svc.ConfirmBooking(context.Background(), "session-1", "u1")
	assert.ErrorIs(t, err, booking.ErrUnauthorized)
}

func TestReleaseBooking_Success(t *testing.T) {
	sl := &mockSeatLock{}
	br := &mockBookingRepo{}
	svc := newService(sl, br, &mockMovieRepo{})

	seats := []booking.Seat{{ID: "A1", Row: "A", Number: 1}}
	b, _ := booking.New("session-1", "u1", "show-1", "movie-1", seats, shared.USD(1500), 10*time.Minute)

	sl.On("GetSession", mock.Anything, "session-1").Return(booking.Session{
		ID: "session-1", UserID: "u1", SeatIDs: []string{"A1"},
	}, nil)
	sl.On("ReleaseSession", mock.Anything, "session-1").Return(nil)
	br.On("FindBySessionID", mock.Anything, "session-1").Return(b, nil)
	br.On("Update", mock.Anything, mock.AnythingOfType("booking.Booking")).Return(nil)

	err := svc.ReleaseBooking(context.Background(), "session-1", "u1")
	require.NoError(t, err)
}
