package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

type BookingHandler struct {
	svc      BookingService
	enricher BookingEnricher // nil = no enrichment
	maxSeats int
}

func NewBookingHandler(svc BookingService, enricher BookingEnricher, maxSeats int) *BookingHandler {
	return &BookingHandler{svc: svc, enricher: enricher, maxSeats: maxSeats}
}

// resolveUserID returns the user ID from the JWT context when auth is enabled,
// falling back to the body-supplied ID for backward-compat / unauthenticated mode.
func resolveUserID(c *gin.Context, bodyUserID string) string {
	if id := c.GetString(middleware.JWTUserIDKey); id != "" {
		return id
	}
	return bodyUserID
}

// POST /showtimes/:showtimeId/hold
func (h *BookingHandler) HoldSeats(c *gin.Context) {
	var req dto.HoldSeatsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	if len(req.SeatIDs) > h.maxSeats {
		status, body := apierr.HTTPStatusFor(booking.ErrMaxSeatsExceeded)
		c.JSON(status, body)
		return
	}

	userID := resolveUserID(c, req.UserID)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, apierr.New("UNAUTHENTICATED", "user_id required"))
		return
	}
	session, err := h.svc.HoldSeats(c.Request.Context(), userID, c.Param("showtimeId"), req.SeatIDs)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
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
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}

	b, err := h.svc.ConfirmBooking(c.Request.Context(), c.Param("sessionId"), resolveUserID(c, req.UserID))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, dto.ToBookingResponse(b))
}

// DELETE /sessions/:sessionId
func (h *BookingHandler) ReleaseBooking(c *gin.Context) {
	var req dto.ConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}

	if err := h.svc.ReleaseBooking(c.Request.Context(), c.Param("sessionId"), resolveUserID(c, req.UserID)); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.Status(http.StatusNoContent)
}

// GET /showtimes/:showtimeId/seats
func (h *BookingHandler) GetSeatMap(c *gin.Context) {
	userID := resolveUserID(c, c.Query("user_id"))
	statuses, err := h.svc.GetSeatMap(c.Request.Context(), c.Param("showtimeId"), userID)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
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

// GET /users/:userId/bookings — JWT sub takes precedence over path param when auth is enabled.
func (h *BookingHandler) GetUserBookings(c *gin.Context) {
	userID := resolveUserID(c, c.Param("userId"))
	if userID == "" {
		c.JSON(http.StatusUnauthorized, apierr.New("UNAUTHENTICATED", "user_id required"))
		return
	}
	bookings, err := h.svc.GetUserBookings(c.Request.Context(), userID)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	// Batch-fetch unique showtimes and their movies for enrichment.
	// Failures are silently skipped — the booking is still returned, just without enrichment.
	type enrichment struct{ movieTitle, hall, startTime, endTime string }
	var cache map[string]enrichment
	if h.enricher != nil {
		cache = make(map[string]enrichment)
		for _, b := range bookings {
			if _, seen := cache[b.ShowtimeID]; seen {
				continue
			}
			st, err := h.enricher.GetShowtime(c.Request.Context(), b.ShowtimeID)
			if err != nil {
				cache[b.ShowtimeID] = enrichment{}
				continue
			}
			title := ""
			if m, err := h.enricher.GetMovie(c.Request.Context(), st.MovieID); err == nil {
				title = m.Title
			}
			cache[b.ShowtimeID] = enrichment{
				movieTitle: title,
				hall:       st.Hall,
				startTime:  st.StartTime.Format(time.RFC3339),
				endTime:    st.EndTime.Format(time.RFC3339),
			}
		}
	}

	resp := make([]dto.BookingResponse, len(bookings))
	for i, b := range bookings {
		r := dto.ToBookingResponse(b)
		if cache != nil {
			if e, ok := cache[b.ShowtimeID]; ok {
				r.MovieTitle = e.movieTitle
				r.Hall = e.hall
				r.StartTime = e.startTime
				r.EndTime = e.endTime
			}
		}
		resp[i] = r
	}
	c.JSON(http.StatusOK, resp)
}
