package handler_test

import (
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

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/handler"
)

// mockMovieSvc implements handler.MovieService for unit tests.
type mockMovieSvc struct{ mock.Mock }

func (m *mockMovieSvc) ListMovies(ctx context.Context) ([]movie.Movie, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]movie.Movie), args.Error(1)
}
func (m *mockMovieSvc) GetMovie(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}
func (m *mockMovieSvc) GetShowtime(ctx context.Context, id string) (movie.Showtime, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Showtime), args.Error(1)
}
func (m *mockMovieSvc) CreateMovie(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockMovieSvc) CreateShowtime(ctx context.Context, st movie.Showtime) error {
	return m.Called(ctx, st).Error(0)
}

func movieRouter(svc handler.MovieService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewMovieHandler(svc)
	r.GET("/movies", h.ListMovies)
	r.GET("/movies/:id", h.GetMovie)
	r.GET("/showtimes/:showtimeId", h.GetShowtime)
	return r
}

func sampleMovie() movie.Movie {
	return movie.Movie{
		ID: "movie-1", Title: "Test Film", Genre: []string{"Action"},
		Rating: 8.1, DurationMin: 120,
		Showtimes: []movie.Showtime{sampleShowtimeForTest()},
	}
}

func sampleShowtimeForTest() movie.Showtime {
	return movie.Showtime{
		ID: "show-1", MovieID: "movie-1", Hall: "Hall A",
		StartTime:   time.Date(2026, 7, 1, 18, 0, 0, 0, time.UTC),
		EndTime:     time.Date(2026, 7, 1, 20, 0, 0, 0, time.UTC),
		Rows: 10, SeatsPerRow: 12,
		Price: shared.NewMoney(1500, "USD"),
	}
}

// --- ListMovies ---

func TestListMovies_ReturnsMovies(t *testing.T) {
	svc := &mockMovieSvc{}
	svc.On("ListMovies", mock.Anything).
		Return([]movie.Movie{sampleMovie()}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/movies", nil)
	movieRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp, 1)
	assert.Equal(t, "movie-1", resp[0]["id"])
	assert.Equal(t, "Test Film", resp[0]["title"])
	svc.AssertExpectations(t)
}

func TestListMovies_EmptyList(t *testing.T) {
	svc := &mockMovieSvc{}
	svc.On("ListMovies", mock.Anything).Return([]movie.Movie{}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/movies", nil)
	movieRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp)
}

// --- GetMovie ---

func TestGetMovie_Found(t *testing.T) {
	svc := &mockMovieSvc{}
	svc.On("GetMovie", mock.Anything, "movie-1").Return(sampleMovie(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/movies/movie-1", nil)
	movieRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "movie-1", resp["id"])
	assert.NotEmpty(t, resp["showtimes"])
	svc.AssertExpectations(t)
}

func TestGetMovie_NotFound(t *testing.T) {
	svc := &mockMovieSvc{}
	svc.On("GetMovie", mock.Anything, "missing").
		Return(movie.Movie{}, movie.ErrMovieNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/movies/missing", nil)
	movieRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "MOVIE_NOT_FOUND", resp["code"])
}

// --- GetShowtime ---

func TestGetShowtime_Found(t *testing.T) {
	svc := &mockMovieSvc{}
	svc.On("GetShowtime", mock.Anything, "show-1").Return(sampleShowtimeForTest(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/showtimes/show-1", nil)
	movieRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "show-1", resp["id"])
	assert.Equal(t, float64(120), resp["total_seats"])
}

func TestGetShowtime_NotFound(t *testing.T) {
	svc := &mockMovieSvc{}
	svc.On("GetShowtime", mock.Anything, "gone").
		Return(movie.Showtime{}, movie.ErrShowtimeNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/showtimes/gone", nil)
	movieRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "SHOWTIME_NOT_FOUND", resp["code"])
}
