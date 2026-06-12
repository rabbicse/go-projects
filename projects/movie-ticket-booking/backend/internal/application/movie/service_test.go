package movie_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

// ── Mock ──────────────────────────────────────────────────────────────────────

type mockMovieRepo struct{ mock.Mock }

func (m *mockMovieRepo) FindAll(ctx context.Context) ([]movie.Movie, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]movie.Movie), args.Error(1)
}
func (m *mockMovieRepo) FindByID(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}
func (m *mockMovieRepo) FindShowtime(ctx context.Context, id string) (movie.Showtime, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Showtime), args.Error(1)
}
func (m *mockMovieRepo) Save(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockMovieRepo) SaveShowtime(ctx context.Context, st movie.Showtime) error {
	return m.Called(ctx, st).Error(0)
}
func (m *mockMovieRepo) UpsertMany(ctx context.Context, movies []movie.Movie) error {
	return m.Called(ctx, movies).Error(0)
}
func (m *mockMovieRepo) Update(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockMovieRepo) Delete(ctx context.Context, id string) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockMovieRepo) DeleteShowtime(ctx context.Context, id string) error {
	return m.Called(ctx, id).Error(0)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newMovieService(repo *mockMovieRepo) *moviesvc.Service {
	return moviesvc.NewService(repo)
}

func validMovieDomain(id string) movie.Movie {
	return movie.Movie{
		ID:          id,
		Title:       "Test Film",
		Genre:       []string{"Action"},
		Rating:      7.5,
		DurationMin: 120,
		Published:   false,
	}
}

// ── ListMovies ────────────────────────────────────────────────────────────────

func TestListMovies_ReturnsList(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("FindAll", mock.Anything).Return([]movie.Movie{
		validMovieDomain("m-1"),
		validMovieDomain("m-2"),
	}, nil)

	movies, err := newMovieService(repo).ListMovies(context.Background())

	require.NoError(t, err)
	assert.Len(t, movies, 2)
}

func TestListMovies_RepoError_PropagatesError(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("FindAll", mock.Anything).Return(nil, assert.AnError)

	_, err := newMovieService(repo).ListMovies(context.Background())

	assert.Error(t, err)
}

// ── GetMovie ──────────────────────────────────────────────────────────────────

func TestGetMovie_Found(t *testing.T) {
	repo := &mockMovieRepo{}
	expected := validMovieDomain("m-1")
	repo.On("FindByID", mock.Anything, "m-1").Return(expected, nil)

	got, err := newMovieService(repo).GetMovie(context.Background(), "m-1")

	require.NoError(t, err)
	assert.Equal(t, expected.ID, got.ID)
}

func TestGetMovie_NotFound_ReturnsErrMovieNotFound(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("FindByID", mock.Anything, "missing").Return(movie.Movie{}, movie.ErrMovieNotFound)

	_, err := newMovieService(repo).GetMovie(context.Background(), "missing")

	assert.ErrorIs(t, err, movie.ErrMovieNotFound)
}

// ── CreateMovie ───────────────────────────────────────────────────────────────

func TestCreateMovie_DelegatesToRepo(t *testing.T) {
	repo := &mockMovieRepo{}
	m := validMovieDomain("new-m")
	repo.On("Save", mock.Anything, m).Return(nil)

	err := newMovieService(repo).CreateMovie(context.Background(), m)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestCreateMovie_RepoError_PropagatesError(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("Save", mock.Anything, mock.Anything).Return(assert.AnError)

	err := newMovieService(repo).CreateMovie(context.Background(), validMovieDomain("m"))

	assert.Error(t, err)
}

// ── UpdateMovie ───────────────────────────────────────────────────────────────

func TestUpdateMovie_DelegatesToRepo(t *testing.T) {
	repo := &mockMovieRepo{}
	m := validMovieDomain("m-1")
	repo.On("Update", mock.Anything, m).Return(nil)

	err := newMovieService(repo).UpdateMovie(context.Background(), m)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ── DeleteMovie ───────────────────────────────────────────────────────────────

func TestDeleteMovie_DelegatesToRepo(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("Delete", mock.Anything, "m-1").Return(nil)

	err := newMovieService(repo).DeleteMovie(context.Background(), "m-1")

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ── PublishMovie ──────────────────────────────────────────────────────────────

func TestPublishMovie_ValidMovie_SetsPublishedAndCallsUpdate(t *testing.T) {
	repo := &mockMovieRepo{}
	m := validMovieDomain("m-1")
	repo.On("FindByID", mock.Anything, "m-1").Return(m, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(updated movie.Movie) bool {
		return updated.ID == "m-1" && updated.Published == true
	})).Return(nil)

	result, err := newMovieService(repo).PublishMovie(context.Background(), "m-1")

	require.NoError(t, err)
	assert.True(t, result.Published)
	repo.AssertExpectations(t)
}

func TestPublishMovie_InvalidMovie_ReturnsValidationError_RepoUpdateNotCalled(t *testing.T) {
	repo := &mockMovieRepo{}
	invalid := movie.Movie{ID: "m-1", Title: "", Genre: nil, DurationMin: 0} // fails Validate
	repo.On("FindByID", mock.Anything, "m-1").Return(invalid, nil)
	// Update must NOT be called.

	_, err := newMovieService(repo).PublishMovie(context.Background(), "m-1")

	var ve *movie.ValidationError
	require.ErrorAs(t, err, &ve)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

func TestPublishMovie_MovieNotFound_ReturnsError(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("FindByID", mock.Anything, "gone").Return(movie.Movie{}, movie.ErrMovieNotFound)

	_, err := newMovieService(repo).PublishMovie(context.Background(), "gone")

	assert.ErrorIs(t, err, movie.ErrMovieNotFound)
}

// ── UnpublishMovie ────────────────────────────────────────────────────────────

func TestUnpublishMovie_SetsPublishedFalseAndCallsUpdate(t *testing.T) {
	repo := &mockMovieRepo{}
	m := validMovieDomain("m-1")
	m.Published = true
	repo.On("FindByID", mock.Anything, "m-1").Return(m, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(updated movie.Movie) bool {
		return updated.ID == "m-1" && updated.Published == false
	})).Return(nil)

	result, err := newMovieService(repo).UnpublishMovie(context.Background(), "m-1")

	require.NoError(t, err)
	assert.False(t, result.Published)
	repo.AssertExpectations(t)
}

// ── CreateShowtime ────────────────────────────────────────────────────────────

func TestCreateShowtime_MovieExists_SavesShowtime(t *testing.T) {
	repo := &mockMovieRepo{}
	st := movie.Showtime{
		ID: "st-1", MovieID: "m-1", Hall: "Hall A",
		Price: shared.USD(1500),
	}
	repo.On("FindByID", mock.Anything, "m-1").Return(validMovieDomain("m-1"), nil)
	repo.On("SaveShowtime", mock.Anything, st).Return(nil)

	err := newMovieService(repo).CreateShowtime(context.Background(), st)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestCreateShowtime_MovieNotFound_ReturnsError(t *testing.T) {
	repo := &mockMovieRepo{}
	repo.On("FindByID", mock.Anything, "gone").Return(movie.Movie{}, movie.ErrMovieNotFound)

	err := newMovieService(repo).CreateShowtime(context.Background(), movie.Showtime{MovieID: "gone"})

	assert.Error(t, err)
}
