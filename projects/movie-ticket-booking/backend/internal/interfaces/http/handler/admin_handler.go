package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

const uploadsDir = "./uploads/posters"

// AdminHandler handles privileged movie/showtime management.
type AdminHandler struct {
	svc     AdminMovieService
	bookSvc AdminBookingService
}

func NewAdminHandler(svc AdminMovieService, bookSvc AdminBookingService) *AdminHandler {
	return &AdminHandler{svc: svc, bookSvc: bookSvc}
}

// GET /api/v1/admin/stats
func (h *AdminHandler) GetStats(c *gin.Context) {
	movies, err := h.svc.ListMovies(c.Request.Context())
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	totalShowtimes := 0
	totalSeats := 0
	for _, m := range movies {
		totalShowtimes += len(m.Showtimes)
		for _, st := range m.Showtimes {
			totalSeats += st.Rows * st.SeatsPerRow
		}
	}

	bStats, err := h.bookSvc.GetStats(c.Request.Context())
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, dto.AdminStatsResponse{
		TotalMovies:       len(movies),
		TotalShowtimes:    totalShowtimes,
		TotalSeats:        totalSeats,
		TotalConfirmed:    bStats.TotalConfirmed,
		TotalRevenueCents: bStats.TotalRevenueCents,
	})
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

// POST /api/v1/admin/movies
func (h *AdminHandler) CreateMovie(c *gin.Context) {
	var req dto.CreateMovieRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
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

// PUT /api/v1/admin/movies/:id
func (h *AdminHandler) UpdateMovie(c *gin.Context) {
	var req dto.UpdateMovieRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	id := c.Param("movieId")
	// Fetch existing to preserve Published status and CreatedAt.
	existing, err := h.svc.GetMovie(c.Request.Context(), id)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	m := movie.Movie{
		ID:          id,
		Title:       req.Title,
		Genre:       req.Genre,
		Rating:      req.Rating,
		PosterURL:   req.PosterURL,
		Description: req.Description,
		DurationMin: req.DurationMin,
		Published:   existing.Published,
		CreatedAt:   existing.CreatedAt,
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.svc.UpdateMovie(c.Request.Context(), m); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	updated, _ := h.svc.GetMovie(c.Request.Context(), m.ID)
	c.JSON(http.StatusOK, dto.ToMovieResponse(updated))
}

// DELETE /api/v1/admin/movies/:id
func (h *AdminHandler) DeleteMovie(c *gin.Context) {
	if err := h.svc.DeleteMovie(c.Request.Context(), c.Param("movieId")); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.Status(http.StatusNoContent)
}

// PUT /api/v1/admin/movies/:id/publish
func (h *AdminHandler) PublishMovie(c *gin.Context) {
	m, err := h.svc.PublishMovie(c.Request.Context(), c.Param("movieId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToMovieResponse(m))
}

// PUT /api/v1/admin/movies/:id/unpublish
func (h *AdminHandler) UnpublishMovie(c *gin.Context) {
	m, err := h.svc.UnpublishMovie(c.Request.Context(), c.Param("movieId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToMovieResponse(m))
}

// POST /api/v1/admin/movies/:id/poster — accepts multipart/form-data with a "poster" file.
func (h *AdminHandler) UploadPoster(c *gin.Context) {
	id := c.Param("movieId")

	existing, err := h.svc.GetMovie(c.Request.Context(), id)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	file, err := c.FormFile("poster")
	if err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", "poster file is required (field: poster)"))
		return
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".webp" {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", "poster must be jpg, jpeg, png, or webp"))
		return
	}

	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, apierr.New("INTERNAL_ERROR", "failed to create upload directory"))
		return
	}

	filename := id + ext
	dst := filepath.Join(uploadsDir, filename)
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, apierr.New("INTERNAL_ERROR", "failed to save poster"))
		return
	}

	posterURL := "/uploads/posters/" + filename
	existing.PosterURL = posterURL
	existing.UpdatedAt = time.Now().UTC()
	if err := h.svc.UpdateMovie(c.Request.Context(), existing); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, gin.H{"poster_url": posterURL})
}

// POST /api/v1/admin/movies/:movieId/showtimes
func (h *AdminHandler) CreateShowtime(c *gin.Context) {
	var req dto.CreateShowtimeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
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

// PUT /api/v1/admin/movies/:movieId/showtimes/:showtimeId
func (h *AdminHandler) UpdateShowtime(c *gin.Context) {
	var req dto.UpdateShowtimeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	st := movie.Showtime{
		ID:          c.Param("showtimeId"),
		MovieID:     c.Param("movieId"),
		Hall:        req.Hall,
		StartTime:   req.StartTime,
		EndTime:     req.EndTime,
		Rows:        req.Rows,
		SeatsPerRow: req.SeatsPerRow,
		Price:       shared.NewMoney(req.PriceCents, req.Currency),
	}
	if err := h.svc.CreateShowtime(c.Request.Context(), st); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToShowtimeResponse(st))
}

// DELETE /api/v1/admin/movies/:movieId/showtimes/:showtimeId
func (h *AdminHandler) DeleteShowtime(c *gin.Context) {
	if err := h.svc.DeleteShowtime(c.Request.Context(), c.Param("showtimeId")); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.Status(http.StatusNoContent)
}
