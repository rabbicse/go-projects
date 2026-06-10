package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

// AdminHandler handles privileged movie/showtime management.
// Protected by HTTP Basic Auth — credentials set via ADMIN_USER / ADMIN_PASSWORD env vars.
type AdminHandler struct {
	svc MovieService
}

func NewAdminHandler(svc MovieService) *AdminHandler {
	return &AdminHandler{svc: svc}
}

// POST /api/v1/admin/movies
func (h *AdminHandler) CreateMovie(c *gin.Context) {
	var req dto.CreateMovieRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", err.Error()))
		return
	}
	if err := h.svc.CreateMovie(c.Request.Context(), req.ToDomain()); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	m, _ := h.svc.GetMovie(c.Request.Context(), req.ID)
	c.JSON(http.StatusCreated, dto.ToMovieResponse(m))
}

// POST /api/v1/admin/movies/:movieId/showtimes
func (h *AdminHandler) CreateShowtime(c *gin.Context) {
	var req dto.CreateShowtimeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", err.Error()))
		return
	}
	st := req.ToDomain(c.Param("movieId"))
	if err := h.svc.CreateShowtime(c.Request.Context(), st); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusCreated, dto.ToShowtimeResponse(st))
}

// GET /api/v1/admin/movies
func (h *AdminHandler) ListMovies(c *gin.Context) {
	movies, err := h.svc.ListMovies(c.Request.Context())
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	resp := make([]dto.MovieResponse, len(movies))
	for i, m := range movies {
		resp[i] = dto.ToMovieResponse(m)
	}
	c.JSON(http.StatusOK, resp)
}
