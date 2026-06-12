package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/handler"
)

// ── Admin service mocks ───────────────────────────────────────────────────────

type mockAdminMovieSvc struct{ mock.Mock }

func (m *mockAdminMovieSvc) ListMovies(ctx context.Context) ([]movie.Movie, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]movie.Movie), args.Error(1)
}
func (m *mockAdminMovieSvc) GetMovie(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}
func (m *mockAdminMovieSvc) GetShowtime(ctx context.Context, id string) (movie.Showtime, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Showtime), args.Error(1)
}
func (m *mockAdminMovieSvc) CreateMovie(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockAdminMovieSvc) CreateShowtime(ctx context.Context, st movie.Showtime) error {
	return m.Called(ctx, st).Error(0)
}
func (m *mockAdminMovieSvc) UpdateMovie(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockAdminMovieSvc) DeleteMovie(ctx context.Context, id string) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockAdminMovieSvc) DeleteShowtime(ctx context.Context, id string) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockAdminMovieSvc) PublishMovie(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}
func (m *mockAdminMovieSvc) UnpublishMovie(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}

type mockAdminBookingSvc struct{ mock.Mock }

func (m *mockAdminBookingSvc) GetStats(ctx context.Context) (booking.BookingStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(booking.BookingStats), args.Error(1)
}

func adminRouter(movieSvc handler.AdminMovieService, bookSvc handler.AdminBookingService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewAdminHandler(movieSvc, bookSvc)
	admin := r.Group("/admin")
	admin.GET("/stats", h.GetStats)
	admin.GET("/movies", h.ListMovies)
	admin.POST("/movies", h.CreateMovie)
	admin.PUT("/movies/:movieId", h.UpdateMovie)
	admin.DELETE("/movies/:movieId", h.DeleteMovie)
	admin.PUT("/movies/:movieId/publish", h.PublishMovie)
	admin.PUT("/movies/:movieId/unpublish", h.UnpublishMovie)
	admin.POST("/movies/:movieId/showtimes", h.CreateShowtime)
	admin.DELETE("/movies/:movieId/showtimes/:showtimeId", h.DeleteShowtime)
	return r
}

func sampleAdminMovie(id string) movie.Movie {
	return movie.Movie{
		ID:          id,
		Title:       "Test Film",
		Genre:       []string{"Action"},
		Rating:      7.5,
		DurationMin: 120,
		Published:   false,
	}
}

func sampleShowtimeBody() map[string]any {
	return map[string]any{
		"id": "st-1", "hall": "Hall A",
		"start_time":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		"end_time":     time.Now().Add(4 * time.Hour).Format(time.RFC3339),
		"rows": 8, "seats_per_row": 10,
		"price_cents": 1500, "currency": "USD",
	}
}

// ── GET /admin/stats ──────────────────────────────────────────────────────────

func TestAdminGetStats_Returns200WithCounts(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	bsvc := &mockAdminBookingSvc{}

	msvc.On("ListMovies", mock.Anything).Return([]movie.Movie{
		{Showtimes: []movie.Showtime{{Rows: 8, SeatsPerRow: 10}}},
	}, nil)
	bsvc.On("GetStats", mock.Anything).Return(booking.BookingStats{
		TotalConfirmed:    5,
		TotalRevenueCents: 7500,
	}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	adminRouter(msvc, bsvc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(1), resp["total_movies"])
	assert.Equal(t, float64(1), resp["total_showtimes"])
	assert.Equal(t, float64(80), resp["total_seats"])
}

// ── GET /admin/movies ─────────────────────────────────────────────────────────

func TestAdminListMovies_ReturnsAllIncludingDrafts(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("ListMovies", mock.Anything).Return([]movie.Movie{
		sampleAdminMovie("m-1"),
		{ID: "m-2", Title: "Draft", Genre: []string{"Drama"}, DurationMin: 90, Published: false},
	}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/movies", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp, 2, "admin list must return all movies including drafts")
}

// ── POST /admin/movies ────────────────────────────────────────────────────────

func TestAdminCreateMovie_Returns201(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("CreateMovie", mock.Anything, mock.AnythingOfType("movie.Movie")).Return(nil)
	msvc.On("GetMovie", mock.Anything, "new-movie").Return(sampleAdminMovie("new-movie"), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/movies", jsonBody(t, map[string]any{
		"id": "new-movie", "title": "New Film", "genre": []string{"Action"},
		"rating": 7.0, "duration_min": 90,
	}))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "new-movie", resp["id"])
}

func TestAdminCreateMovie_MissingTitle_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/movies", jsonBody(t, map[string]any{
		"id": "m-1", "genre": []string{"Action"}, "rating": 7.0, "duration_min": 90,
		// no "title"
	}))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(&mockAdminMovieSvc{}, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateMovie_InvalidJSON_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/movies",
		bytes.NewBufferString(`{not valid json`))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(&mockAdminMovieSvc{}, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── PUT /admin/movies/:movieId ────────────────────────────────────────────────

func TestAdminUpdateMovie_PreservesPublishedStatus(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	existing := sampleAdminMovie("m-1")
	existing.Published = true // published before update

	msvc.On("GetMovie", mock.Anything, "m-1").Return(existing, nil)
	msvc.On("UpdateMovie", mock.Anything, mock.MatchedBy(func(m movie.Movie) bool {
		return m.ID == "m-1" && m.Published == true // must preserve published=true
	})).Return(nil)
	msvc.On("GetMovie", mock.Anything, "m-1").Return(existing, nil) // second call for response

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/movies/m-1", jsonBody(t, map[string]any{
		"title": "Updated Title", "genre": []string{"Drama"},
		"rating": 8.0, "duration_min": 100,
	}))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminUpdateMovie_MovieNotFound_Returns404(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("GetMovie", mock.Anything, "gone").Return(movie.Movie{}, movie.ErrMovieNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/movies/gone", jsonBody(t, map[string]any{
		"title": "X", "genre": []string{"Drama"}, "rating": 7.0, "duration_min": 90,
	}))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── DELETE /admin/movies/:movieId ─────────────────────────────────────────────

func TestAdminDeleteMovie_Returns204(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("DeleteMovie", mock.Anything, "m-1").Return(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/movies/m-1", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	msvc.AssertExpectations(t)
}

func TestAdminDeleteMovie_NotFound_Returns404(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("DeleteMovie", mock.Anything, "gone").Return(movie.ErrMovieNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/movies/gone", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── PUT /admin/movies/:movieId/publish ────────────────────────────────────────

func TestAdminPublishMovie_Returns200WithPublishedTrue(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	published := sampleAdminMovie("m-1")
	published.Published = true
	msvc.On("PublishMovie", mock.Anything, "m-1").Return(published, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/movies/m-1/publish", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["published"])
}

func TestAdminPublishMovie_ValidationError_Returns422(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("PublishMovie", mock.Anything, "draft").
		Return(movie.Movie{}, &movie.ValidationError{Messages: []string{"title is required"}})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/movies/draft/publish", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "VALIDATION_ERROR", resp["code"])
}

func TestAdminPublishMovie_NotFound_Returns404(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("PublishMovie", mock.Anything, "gone").Return(movie.Movie{}, movie.ErrMovieNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/movies/gone/publish", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── PUT /admin/movies/:movieId/unpublish ──────────────────────────────────────

func TestAdminUnpublishMovie_Returns200WithPublishedFalse(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	unpublished := sampleAdminMovie("m-1")
	unpublished.Published = false
	msvc.On("UnpublishMovie", mock.Anything, "m-1").Return(unpublished, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/movies/m-1/unpublish", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["published"])
}

// ── POST /admin/movies/:movieId/showtimes ─────────────────────────────────────

func TestAdminCreateShowtime_Returns201(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("CreateShowtime", mock.Anything, mock.AnythingOfType("movie.Showtime")).Return(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/movies/m-1/showtimes",
		jsonBody(t, sampleShowtimeBody()))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestAdminCreateShowtime_MissingHall_Returns400(t *testing.T) {
	body := sampleShowtimeBody()
	delete(body, "hall")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/movies/m-1/showtimes", jsonBody(t, body))
	req.Header.Set("Content-Type", "application/json")
	adminRouter(&mockAdminMovieSvc{}, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DELETE /admin/movies/:movieId/showtimes/:showtimeId ───────────────────────

func TestAdminDeleteShowtime_Returns204(t *testing.T) {
	msvc := &mockAdminMovieSvc{}
	msvc.On("DeleteShowtime", mock.Anything, "st-1").Return(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/movies/m-1/showtimes/st-1", nil)
	adminRouter(msvc, &mockAdminBookingSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

