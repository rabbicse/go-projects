package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

type MovieHandler struct {
	svc *moviesvc.Service
}

func NewMovieHandler(svc *moviesvc.Service) *MovieHandler {
	return &MovieHandler{svc: svc}
}

// GET /movies
func (h *MovieHandler) ListMovies(c *gin.Context) {
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

// GET /movies/:id
func (h *MovieHandler) GetMovie(c *gin.Context) {
	m, err := h.svc.GetMovie(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.ToMovieResponse(m))
}

// GET /showtimes/:showtimeId
func (h *MovieHandler) GetShowtime(c *gin.Context) {
	st, err := h.svc.GetShowtime(c.Request.Context(), c.Param("showtimeId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto.ToShowtimeResponse(st))
}
