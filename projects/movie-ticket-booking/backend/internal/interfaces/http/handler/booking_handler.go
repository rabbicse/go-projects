package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

type BookingHandler struct {
	svc      *bookingsvc.Service
	maxSeats int
}

func NewBookingHandler(svc *bookingsvc.Service, maxSeats int) *BookingHandler {
	return &BookingHandler{svc: svc, maxSeats: maxSeats}
}

// POST /showtimes/:showtimeId/hold
func (h *BookingHandler) HoldSeats(c *gin.Context) {
	var req dto.HoldSeatsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.SeatIDs) > h.maxSeats {
		c.JSON(http.StatusBadRequest, gin.H{"error": booking.ErrMaxSeatsExceeded.Error()})
		return
	}

	session, err := h.svc.HoldSeats(c.Request.Context(), req.UserID, c.Param("showtimeId"), req.SeatIDs)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, booking.ErrSeatAlreadyHeld) {
			status = http.StatusConflict
		} else if errors.Is(err, booking.ErrMaxSeatsExceeded) || errors.Is(err, booking.ErrNoSeatsSelected) {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, dto.HoldSeatsResponse{
		SessionID:  session.ID,
		ShowtimeID: session.ShowtimeID,
		MovieID:    session.MovieID,
		SeatIDs:    session.SeatIDs,
		Status:     string(session.Status),
		ExpiresAt:  session.ExpiresAt,
	})
}

// PUT /sessions/:sessionId/confirm
func (h *BookingHandler) ConfirmBooking(c *gin.Context) {
	var req dto.ConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	b, err := h.svc.ConfirmBooking(c.Request.Context(), c.Param("sessionId"), req.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, booking.ErrSessionNotFound):
			status = http.StatusNotFound
		case errors.Is(err, booking.ErrUnauthorized):
			status = http.StatusForbidden
		case errors.Is(err, booking.ErrSessionExpired):
			status = http.StatusGone
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.ToBookingResponse(b))
}

// DELETE /sessions/:sessionId
func (h *BookingHandler) ReleaseBooking(c *gin.Context) {
	var req dto.ConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.ReleaseBooking(c.Request.Context(), c.Param("sessionId"), req.UserID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, booking.ErrSessionNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, booking.ErrUnauthorized) {
			status = http.StatusForbidden
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// GET /showtimes/:showtimeId/seats
func (h *BookingHandler) GetSeatMap(c *gin.Context) {
	userID := c.Query("user_id")
	statuses, err := h.svc.GetSeatMap(c.Request.Context(), c.Param("showtimeId"), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.SeatStatusResponse, len(statuses))
	for i, s := range statuses {
		resp[i] = dto.SeatStatusResponse{
			SeatID:    s.SeatID,
			Status:    s.Status,
			HeldByMe:  s.HeldByMe,
			ExpiresAt: s.ExpiresAt,
		}
	}
	c.JSON(http.StatusOK, resp)
}

// GET /users/:userId/bookings
func (h *BookingHandler) GetUserBookings(c *gin.Context) {
	bookings, err := h.svc.GetUserBookings(c.Request.Context(), c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.BookingResponse, len(bookings))
	for i, b := range bookings {
		resp[i] = dto.ToBookingResponse(b)
	}
	c.JSON(http.StatusOK, resp)
}
