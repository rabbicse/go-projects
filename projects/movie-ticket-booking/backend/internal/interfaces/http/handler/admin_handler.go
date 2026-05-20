package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

// AdminHandler handles privileged movie/showtime management.
// Protected by HTTP Basic Auth (admin/admin).
type AdminHandler struct {
	svc *moviesvc.Service
}

func NewAdminHandler(svc *moviesvc.Service) *AdminHandler {
	return &AdminHandler{svc: svc}
}

// POST /api/v1/admin/movies
func (h *AdminHandler) CreateMovie(c *gin.Context) {
	var req dto.CreateMovieRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.CreateMovie(c.Request.Context(), req.ToDomain()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	m, _ := h.svc.GetMovie(c.Request.Context(), req.ID)
	c.JSON(http.StatusCreated, dto.ToMovieResponse(m))
}

// POST /api/v1/admin/movies/:movieId/showtimes
func (h *AdminHandler) CreateShowtime(c *gin.Context) {
	var req dto.CreateShowtimeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	st := req.ToDomain(c.Param("movieId"))
	if err := h.svc.CreateShowtime(c.Request.Context(), st); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, dto.ToShowtimeResponse(st))
}

// GET /api/v1/admin/movies  (same as public but auth-gated for admin UI convenience)
func (h *AdminHandler) ListMovies(c *gin.Context) {
	movies, err := h.svc.ListMovies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]dto.MovieResponse, len(movies))
	for i, m := range movies {
		resp[i] = dto.ToMovieResponse(m)
	}
	c.JSON(http.StatusOK, resp)
}
