package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	showdomain "github.com/rabbicse/movie-ticket-booking/internal/domain/show"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

type ShowHandler struct {
	svc ShowService
}

func NewShowHandler(svc ShowService) *ShowHandler {
	return &ShowHandler{svc: svc}
}

// GET /api/v1/admin/shows
func (h *ShowHandler) ListShows(c *gin.Context) {
	shows, err := h.svc.ListShows(c.Request.Context())
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	resp := make([]dto.ShowResponse, len(shows))
	for i, s := range shows {
		resp[i] = dto.ToShowResponse(s)
	}
	c.JSON(http.StatusOK, resp)
}

// GET /api/v1/admin/shows/:showId
func (h *ShowHandler) GetShow(c *gin.Context) {
	s, err := h.svc.GetShow(c.Request.Context(), c.Param("showId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToShowResponse(s))
}

// POST /api/v1/admin/shows
func (h *ShowHandler) CreateShow(c *gin.Context) {
	var req dto.CreateShowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	s := req.ToDomain()
	if err := h.svc.CreateShow(c.Request.Context(), s); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	created, _ := h.svc.GetShow(c.Request.Context(), s.ID)
	c.JSON(http.StatusCreated, dto.ToShowResponse(created))
}

// PUT /api/v1/admin/shows/:showId
func (h *ShowHandler) UpdateShow(c *gin.Context) {
	var req dto.UpdateShowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	id := c.Param("showId")
	existing, err := h.svc.GetShow(c.Request.Context(), id)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	s := showdomain.Show{
		ID:        id,
		MovieID:   req.MovieID,
		ScreenID:  req.ScreenID,
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
		Status:    existing.Status,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now().UTC(),
	}
	if err := h.svc.UpdateShow(c.Request.Context(), s); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	updated, _ := h.svc.GetShow(c.Request.Context(), id)
	c.JSON(http.StatusOK, dto.ToShowResponse(updated))
}

// PUT /api/v1/admin/shows/:showId/cancel
func (h *ShowHandler) CancelShow(c *gin.Context) {
	s, err := h.svc.CancelShow(c.Request.Context(), c.Param("showId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToShowResponse(s))
}
