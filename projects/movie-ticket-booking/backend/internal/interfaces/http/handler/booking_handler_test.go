package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/handler"
)

// mockBookingSvc implements handler.BookingService for unit tests.
type mockBookingSvc struct{ mock.Mock }

func (m *mockBookingSvc) HoldSeats(ctx context.Context, userID, showtimeID string, seatIDs []string) (booking.Session, error) {
	args := m.Called(ctx, userID, showtimeID, seatIDs)
	return args.Get(0).(booking.Session), args.Error(1)
}
func (m *mockBookingSvc) ConfirmBooking(ctx context.Context, sessionID, userID string) (booking.Booking, error) {
	args := m.Called(ctx, sessionID, userID)
	return args.Get(0).(booking.Booking), args.Error(1)
}
func (m *mockBookingSvc) ReleaseBooking(ctx context.Context, sessionID, userID string) error {
	return m.Called(ctx, sessionID, userID).Error(0)
}
func (m *mockBookingSvc) GetSeatMap(ctx context.Context, showtimeID, userID string) ([]booking.SeatStatus, error) {
	args := m.Called(ctx, showtimeID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]booking.SeatStatus), args.Error(1)
}
func (m *mockBookingSvc) GetUserBookings(ctx context.Context, userID string) ([]booking.Booking, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]booking.Booking), args.Error(1)
}

func bookingRouter(svc handler.BookingService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewBookingHandler(svc, 4)
	r.POST("/showtimes/:showtimeId/hold", h.HoldSeats)
	r.PUT("/sessions/:sessionId/confirm", h.ConfirmBooking)
	r.DELETE("/sessions/:sessionId", h.ReleaseBooking)
	r.GET("/showtimes/:showtimeId/seats", h.GetSeatMap)
	r.GET("/users/:userId/bookings", h.GetUserBookings)
	return r
}

func jsonBody(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// --- HoldSeats ---

func TestHoldSeats_Success(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("HoldSeats", mock.Anything, "u1", "show-1", []string{"A1"}).
		Return(booking.Session{
			ID: "sess-1", UserID: "u1", ShowtimeID: "show-1", MovieID: "movie-1",
			SeatIDs: []string{"A1"}, Status: booking.StatusHeld,
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/showtimes/show-1/hold",
		jsonBody(t, map[string]any{"user_id": "u1", "seat_ids": []string{"A1"}}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "sess-1", resp["session_id"])
	assert.Equal(t, "held", resp["status"])
	svc.AssertExpectations(t)
}

func TestHoldSeats_TooManySeats(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/showtimes/show-1/hold",
		jsonBody(t, map[string]any{
			"user_id":  "u1",
			"seat_ids": []string{"A1", "A2", "A3", "A4", "A5"}, // exceeds maxSeats=4
		}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(&mockBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "MAX_SEATS_EXCEEDED", resp["code"])
}

func TestHoldSeats_SeatAlreadyHeld(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("HoldSeats", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(booking.Session{}, booking.ErrSeatAlreadyHeld)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/showtimes/show-1/hold",
		jsonBody(t, map[string]any{"user_id": "u1", "seat_ids": []string{"A1"}}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "SEATS_UNAVAILABLE", resp["code"])
}

func TestHoldSeats_InvalidBody(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/showtimes/show-1/hold",
		bytes.NewBufferString(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(&mockBookingSvc{}).ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- ConfirmBooking ---

func TestConfirmBooking_Success(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("ConfirmBooking", mock.Anything, "sess-1", "u1").
		Return(booking.Booking{
			ID: "bk-1", SessionID: "sess-1", UserID: "u1",
			ShowtimeID: "show-1", MovieID: "movie-1",
			Status: booking.StatusConfirmed,
		}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sessions/sess-1/confirm",
		jsonBody(t, map[string]any{"user_id": "u1"}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "confirmed", resp["status"])
	svc.AssertExpectations(t)
}

func TestConfirmBooking_Unauthorized(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("ConfirmBooking", mock.Anything, mock.Anything, mock.Anything).
		Return(booking.Booking{}, booking.ErrUnauthorized)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sessions/sess-1/confirm",
		jsonBody(t, map[string]any{"user_id": "attacker"}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "UNAUTHORIZED", resp["code"])
}

func TestConfirmBooking_SessionExpired(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("ConfirmBooking", mock.Anything, mock.Anything, mock.Anything).
		Return(booking.Booking{}, booking.ErrSessionExpired)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sessions/sess-1/confirm",
		jsonBody(t, map[string]any{"user_id": "u1"}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code)
}

// --- ReleaseBooking ---

func TestReleaseBooking_Success(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("ReleaseBooking", mock.Anything, "sess-1", "u1").Return(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/sessions/sess-1",
		jsonBody(t, map[string]any{"user_id": "u1"}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	svc.AssertExpectations(t)
}

func TestReleaseBooking_SessionNotFound(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("ReleaseBooking", mock.Anything, mock.Anything, mock.Anything).
		Return(booking.ErrSessionNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/sessions/sess-gone",
		jsonBody(t, map[string]any{"user_id": "u1"}))
	req.Header.Set("Content-Type", "application/json")
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- GetSeatMap ---

func TestGetSeatMap_Success(t *testing.T) {
	ttl := int64(300)
	svc := &mockBookingSvc{}
	svc.On("GetSeatMap", mock.Anything, "show-1", "u1").
		Return([]booking.SeatStatus{
			{SeatID: "A1", Status: "held", HeldByMe: true, ExpiresAt: &ttl},
			{SeatID: "A2", Status: "confirmed"},
		}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/showtimes/show-1/seats?user_id=u1", nil)
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp, 2)
	svc.AssertExpectations(t)
}

// --- GetUserBookings ---

func TestGetUserBookings_ReturnsBookings(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("GetUserBookings", mock.Anything, "u1").
		Return([]booking.Booking{
			{ID: "bk-1", UserID: "u1", Status: booking.StatusConfirmed},
		}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/u1/bookings", nil)
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp, 1)
	assert.Equal(t, "bk-1", resp[0]["id"])
	svc.AssertExpectations(t)
}

func TestGetUserBookings_ServiceError(t *testing.T) {
	svc := &mockBookingSvc{}
	svc.On("GetUserBookings", mock.Anything, "u1").
		Return(nil, errors.New("db down"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/u1/bookings", nil)
	bookingRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
