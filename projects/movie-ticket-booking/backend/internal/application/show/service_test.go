package show_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	showsvc "github.com/rabbicse/movie-ticket-booking/internal/application/show"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
)

// ── Mocks ─────────────────────────────────────────────────────────────────────

type mockShowRepo struct{ mock.Mock }

func (m *mockShowRepo) FindAll(ctx context.Context) ([]show.Show, error) {
	args := m.Called(ctx)
	return args.Get(0).([]show.Show), args.Error(1)
}
func (m *mockShowRepo) FindByID(ctx context.Context, id string) (show.Show, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(show.Show), args.Error(1)
}
func (m *mockShowRepo) FindByScreenAndTimeRange(ctx context.Context, screenID string, start, end time.Time) ([]show.Show, error) {
	args := m.Called(ctx, screenID, start, end)
	return args.Get(0).([]show.Show), args.Error(1)
}
func (m *mockShowRepo) Save(ctx context.Context, s show.Show) error {
	return m.Called(ctx, s).Error(0)
}
func (m *mockShowRepo) Update(ctx context.Context, s show.Show) error {
	return m.Called(ctx, s).Error(0)
}

type mockMovieRepo struct{ mock.Mock }

func (m *mockMovieRepo) FindAll(ctx context.Context) ([]movie.Movie, error) {
	args := m.Called(ctx)
	return args.Get(0).([]movie.Movie), args.Error(1)
}
func (m *mockMovieRepo) FindByID(ctx context.Context, id string) (movie.Movie, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(movie.Movie), args.Error(1)
}
func (m *mockMovieRepo) FindShowtime(ctx context.Context, showtimeID string) (movie.Showtime, error) {
	args := m.Called(ctx, showtimeID)
	return args.Get(0).(movie.Showtime), args.Error(1)
}
func (m *mockMovieRepo) Save(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockMovieRepo) SaveShowtime(ctx context.Context, s movie.Showtime) error {
	return m.Called(ctx, s).Error(0)
}
func (m *mockMovieRepo) Update(ctx context.Context, mv movie.Movie) error {
	return m.Called(ctx, mv).Error(0)
}
func (m *mockMovieRepo) UpsertMany(ctx context.Context, movies []movie.Movie) error {
	return m.Called(ctx, movies).Error(0)
}
func (m *mockMovieRepo) Delete(ctx context.Context, id string) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockMovieRepo) DeleteShowtime(ctx context.Context, showtimeID string) error {
	return m.Called(ctx, showtimeID).Error(0)
}

type mockTheaterRepo struct{ mock.Mock }

func (m *mockTheaterRepo) FindAll(ctx context.Context) ([]theater.Theater, error) {
	args := m.Called(ctx)
	return args.Get(0).([]theater.Theater), args.Error(1)
}
func (m *mockTheaterRepo) FindByID(ctx context.Context, id string) (theater.Theater, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(theater.Theater), args.Error(1)
}
func (m *mockTheaterRepo) Save(ctx context.Context, t theater.Theater) error {
	return m.Called(ctx, t).Error(0)
}
func (m *mockTheaterRepo) Update(ctx context.Context, t theater.Theater) error {
	return m.Called(ctx, t).Error(0)
}
func (m *mockTheaterRepo) FindScreensByTheater(ctx context.Context, theaterID string) ([]theater.Screen, error) {
	args := m.Called(ctx, theaterID)
	return args.Get(0).([]theater.Screen), args.Error(1)
}
func (m *mockTheaterRepo) FindScreenByID(ctx context.Context, id string) (theater.Screen, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(theater.Screen), args.Error(1)
}
func (m *mockTheaterRepo) SaveScreen(ctx context.Context, s theater.Screen) error {
	return m.Called(ctx, s).Error(0)
}
func (m *mockTheaterRepo) UpdateScreen(ctx context.Context, s theater.Screen) error {
	return m.Called(ctx, s).Error(0)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func activeScreen() theater.Screen {
	return theater.Screen{ID: "scr-1", TheaterID: "t-1", Name: "Screen 1", Status: theater.ScreenStatusActive}
}

func futureShow() show.Show {
	base := time.Now().UTC().Add(24 * time.Hour)
	return show.Show{
		ID:        "sh-1",
		MovieID:   "mv-1",
		ScreenID:  "scr-1",
		StartTime: base,
		EndTime:   base.Add(2 * time.Hour),
		Status:    show.ShowStatusScheduled,
	}
}

// ── CreateShow tests ──────────────────────────────────────────────────────────

func TestShowService_CreateShow_HappyPath(t *testing.T) {
	showRepo := new(mockShowRepo)
	movieRepo := new(mockMovieRepo)
	theaterRepo := new(mockTheaterRepo)
	svc := showsvc.NewService(showRepo, movieRepo, theaterRepo)

	s := futureShow()
	movieRepo.On("FindByID", mock.Anything, "mv-1").Return(movie.Movie{ID: "mv-1"}, nil)
	theaterRepo.On("FindScreenByID", mock.Anything, "scr-1").Return(activeScreen(), nil)
	showRepo.On("FindByScreenAndTimeRange", mock.Anything, "scr-1", s.StartTime, s.EndTime).Return([]show.Show{}, nil)
	showRepo.On("Save", mock.Anything, s).Return(nil)

	err := svc.CreateShow(context.Background(), s)
	require.NoError(t, err)
	showRepo.AssertExpectations(t)
}

func TestShowService_CreateShow_InvalidTimeOrder(t *testing.T) {
	svc := showsvc.NewService(new(mockShowRepo), new(mockMovieRepo), new(mockTheaterRepo))
	now := time.Now().UTC()
	s := show.Show{StartTime: now.Add(2 * time.Hour), EndTime: now.Add(1 * time.Hour)}

	err := svc.CreateShow(context.Background(), s)
	require.Error(t, err)
	var ve *show.ValidationError
	assert.ErrorAs(t, err, &ve)
}

func TestShowService_CreateShow_SameStartEnd(t *testing.T) {
	svc := showsvc.NewService(new(mockShowRepo), new(mockMovieRepo), new(mockTheaterRepo))
	now := time.Now().UTC().Add(time.Hour)
	s := show.Show{StartTime: now, EndTime: now}

	err := svc.CreateShow(context.Background(), s)
	var ve *show.ValidationError
	assert.ErrorAs(t, err, &ve)
}

func TestShowService_CreateShow_MovieNotFound(t *testing.T) {
	showRepo := new(mockShowRepo)
	movieRepo := new(mockMovieRepo)
	theaterRepo := new(mockTheaterRepo)
	svc := showsvc.NewService(showRepo, movieRepo, theaterRepo)

	s := futureShow()
	movieRepo.On("FindByID", mock.Anything, "mv-1").Return(movie.Movie{}, movie.ErrMovieNotFound)

	err := svc.CreateShow(context.Background(), s)
	assert.ErrorIs(t, err, movie.ErrMovieNotFound)
}

func TestShowService_CreateShow_DisabledScreen(t *testing.T) {
	showRepo := new(mockShowRepo)
	movieRepo := new(mockMovieRepo)
	theaterRepo := new(mockTheaterRepo)
	svc := showsvc.NewService(showRepo, movieRepo, theaterRepo)

	s := futureShow()
	disabled := activeScreen()
	disabled.Status = theater.ScreenStatusDisabled

	movieRepo.On("FindByID", mock.Anything, "mv-1").Return(movie.Movie{ID: "mv-1"}, nil)
	theaterRepo.On("FindScreenByID", mock.Anything, "scr-1").Return(disabled, nil)

	err := svc.CreateShow(context.Background(), s)
	var ve *show.ValidationError
	assert.ErrorAs(t, err, &ve)
	assert.Contains(t, err.Error(), "disabled")
}

func TestShowService_CreateShow_OverlapConflict(t *testing.T) {
	showRepo := new(mockShowRepo)
	movieRepo := new(mockMovieRepo)
	theaterRepo := new(mockTheaterRepo)
	svc := showsvc.NewService(showRepo, movieRepo, theaterRepo)

	s := futureShow()
	conflicting := show.Show{ID: "other", ScreenID: "scr-1", StartTime: s.StartTime, EndTime: s.EndTime}

	movieRepo.On("FindByID", mock.Anything, "mv-1").Return(movie.Movie{ID: "mv-1"}, nil)
	theaterRepo.On("FindScreenByID", mock.Anything, "scr-1").Return(activeScreen(), nil)
	showRepo.On("FindByScreenAndTimeRange", mock.Anything, "scr-1", s.StartTime, s.EndTime).Return([]show.Show{conflicting}, nil)

	err := svc.CreateShow(context.Background(), s)
	assert.ErrorIs(t, err, show.ErrShowConflict)
}

// ── CancelShow tests ──────────────────────────────────────────────────────────

func TestShowService_CancelShow_HappyPath(t *testing.T) {
	showRepo := new(mockShowRepo)
	svc := showsvc.NewService(showRepo, new(mockMovieRepo), new(mockTheaterRepo))

	s := futureShow()
	showRepo.On("FindByID", mock.Anything, "sh-1").Return(s, nil)
	showRepo.On("Update", mock.Anything, mock.MatchedBy(func(u show.Show) bool {
		return u.Status == show.ShowStatusCancelled
	})).Return(nil)

	result, err := svc.CancelShow(context.Background(), "sh-1")
	require.NoError(t, err)
	assert.Equal(t, show.ShowStatusCancelled, result.Status)
	showRepo.AssertExpectations(t)
}

func TestShowService_CancelShow_AlreadyCancelled(t *testing.T) {
	showRepo := new(mockShowRepo)
	svc := showsvc.NewService(showRepo, new(mockMovieRepo), new(mockTheaterRepo))

	s := futureShow()
	s.Status = show.ShowStatusCancelled
	showRepo.On("FindByID", mock.Anything, "sh-1").Return(s, nil)

	_, err := svc.CancelShow(context.Background(), "sh-1")
	assert.ErrorIs(t, err, show.ErrShowCancelled)
}
