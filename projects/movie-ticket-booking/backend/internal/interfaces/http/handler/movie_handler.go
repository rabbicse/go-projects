package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

type MovieHandler struct {
	svc MovieService
}

func NewMovieHandler(svc MovieService) *MovieHandler {
	return &MovieHandler{svc: svc}
}

// GET /movies — returns only published movies.
func (h *MovieHandler) ListMovies(c *gin.Context) {
	all, err := h.svc.ListMovies(c.Request.Context())
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	resp := make([]dto.MovieResponse, 0, len(all))
	for _, m := range all {
		if m.Published {
			resp = append(resp, dto.ToMovieResponse(m))
		}
	}
	c.JSON(http.StatusOK, resp)
}

// GET /movies/:id
func (h *MovieHandler) GetMovie(c *gin.Context) {
	m, err := h.svc.GetMovie(c.Request.Context(), c.Param("id"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToMovieResponse(m))
}

// GET /showtimes/:showtimeId
func (h *MovieHandler) GetShowtime(c *gin.Context) {
	st, err := h.svc.GetShowtime(c.Request.Context(), c.Param("showtimeId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToShowtimeResponse(st))
}
