package theater_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	theatersvc "github.com/rabbicse/movie-ticket-booking/internal/application/theater"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
)

// ── Mock ──────────────────────────────────────────────────────────────────────

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

// ── Theater tests ─────────────────────────────────────────────────────────────

func TestTheaterService_CreateTheater(t *testing.T) {
	repo := new(mockTheaterRepo)
	svc := theatersvc.NewService(repo)

	th := theater.Theater{ID: "t1", Name: "Grand", Location: "Downtown", Status: theater.TheaterStatusActive}
	repo.On("Save", mock.Anything, th).Return(nil)

	err := svc.CreateTheater(context.Background(), th)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestTheaterService_DisableTheater(t *testing.T) {
	repo := new(mockTheaterRepo)
	svc := theatersvc.NewService(repo)

	now := time.Now().UTC()
	existing := theater.Theater{
		ID: "t1", Name: "Grand", Location: "Downtown",
		Status: theater.TheaterStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	repo.On("FindByID", mock.Anything, "t1").Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(t theater.Theater) bool {
		return t.Status == theater.TheaterStatusDisabled
	})).Return(nil)

	result, err := svc.DisableTheater(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, theater.TheaterStatusDisabled, result.Status)
	repo.AssertExpectations(t)
}

func TestTheaterService_DisableTheater_NotFound(t *testing.T) {
	repo := new(mockTheaterRepo)
	svc := theatersvc.NewService(repo)

	repo.On("FindByID", mock.Anything, "missing").Return(theater.Theater{}, theater.ErrTheaterNotFound)

	_, err := svc.DisableTheater(context.Background(), "missing")
	assert.ErrorIs(t, err, theater.ErrTheaterNotFound)
}

// ── Screen tests ──────────────────────────────────────────────────────────────

func TestTheaterService_ListScreens_TheaterNotFound(t *testing.T) {
	repo := new(mockTheaterRepo)
	svc := theatersvc.NewService(repo)

	repo.On("FindByID", mock.Anything, "bad").Return(theater.Theater{}, theater.ErrTheaterNotFound)

	_, err := svc.ListScreens(context.Background(), "bad")
	assert.ErrorIs(t, err, theater.ErrTheaterNotFound)
}

func TestTheaterService_CreateScreen(t *testing.T) {
	repo := new(mockTheaterRepo)
	svc := theatersvc.NewService(repo)

	th := theater.Theater{ID: "t1", Status: theater.TheaterStatusActive}
	sc := theater.Screen{ID: "s1", TheaterID: "t1", Name: "Screen 1", Status: theater.ScreenStatusActive}

	repo.On("FindByID", mock.Anything, "t1").Return(th, nil)
	repo.On("SaveScreen", mock.Anything, sc).Return(nil)

	err := svc.CreateScreen(context.Background(), sc)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestTheaterService_DisableScreen(t *testing.T) {
	repo := new(mockTheaterRepo)
	svc := theatersvc.NewService(repo)

	now := time.Now().UTC()
	existing := theater.Screen{
		ID: "s1", TheaterID: "t1", Name: "Screen 1",
		Status: theater.ScreenStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	repo.On("FindScreenByID", mock.Anything, "s1").Return(existing, nil)
	repo.On("UpdateScreen", mock.Anything, mock.MatchedBy(func(s theater.Screen) bool {
		return s.Status == theater.ScreenStatusDisabled
	})).Return(nil)

	result, err := svc.DisableScreen(context.Background(), "s1")
	require.NoError(t, err)
	assert.Equal(t, theater.ScreenStatusDisabled, result.Status)
	repo.AssertExpectations(t)
}
