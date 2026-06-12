package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
)

func sampleMovie(id string) movie.Movie {
	return movie.Movie{
		ID:          id,
		Title:       "Integration Test Film",
		Genre:       []string{"Action", "Drama"},
		Rating:      8.0,
		DurationMin: 120,
		Published:   false,
	}
}

func sampleShowtime(id, movieID string) movie.Showtime {
	return movie.Showtime{
		ID:          id,
		MovieID:     movieID,
		Hall:        "Hall A",
		StartTime:   time.Now().Add(2 * time.Hour).UTC().Truncate(time.Millisecond),
		EndTime:     time.Now().Add(4 * time.Hour).UTC().Truncate(time.Millisecond),
		Rows:        8,
		SeatsPerRow: 10,
		Price:       shared.USD(1500),
	}
}

// ── Save + FindByID ───────────────────────────────────────────────────────────

func TestMovieRepo_SaveAndFindByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	m := sampleMovie("movie-it-1")
	require.NoError(t, repo.Save(ctx, m))

	found, err := repo.FindByID(ctx, "movie-it-1")
	require.NoError(t, err)
	assert.Equal(t, m.ID, found.ID)
	assert.Equal(t, m.Title, found.Title)
	assert.Equal(t, m.Genre, found.Genre)
	assert.Equal(t, m.Rating, found.Rating)
	assert.Equal(t, m.DurationMin, found.DurationMin)
	assert.False(t, found.Published)
}

func TestMovieRepo_FindByID_NotFound_ReturnsErrMovieNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "does-not-exist")
	assert.ErrorIs(t, err, movie.ErrMovieNotFound)
}

// ── FindAll ───────────────────────────────────────────────────────────────────

func TestMovieRepo_FindAll_ReturnsAllMovies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	require.NoError(t, repo.Save(ctx, sampleMovie("m-1")))
	require.NoError(t, repo.Save(ctx, sampleMovie("m-2")))
	require.NoError(t, repo.Save(ctx, sampleMovie("m-3")))

	movies, err := repo.FindAll(ctx)
	require.NoError(t, err)
	assert.Len(t, movies, 3)
}

func TestMovieRepo_FindAll_EmptyCollection_ReturnsNil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	movies, err := repo.FindAll(ctx)
	require.NoError(t, err)
	assert.Nil(t, movies)
}

// ── Update ────────────────────────────────────────────────────────────────────

func TestMovieRepo_Update_PersistsChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	m := sampleMovie("movie-update-1")
	require.NoError(t, repo.Save(ctx, m))

	m.Title = "Updated Title"
	m.Published = true
	require.NoError(t, repo.Update(ctx, m))

	found, err := repo.FindByID(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Title", found.Title)
	assert.True(t, found.Published)
}

func TestMovieRepo_Update_NotFound_ReturnsErrMovieNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	err := repo.Update(ctx, sampleMovie("ghost-movie"))
	assert.ErrorIs(t, err, movie.ErrMovieNotFound)
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestMovieRepo_Delete_RemovesDocument(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	m := sampleMovie("movie-del-1")
	require.NoError(t, repo.Save(ctx, m))
	require.NoError(t, repo.Delete(ctx, m.ID))

	_, err := repo.FindByID(ctx, m.ID)
	assert.ErrorIs(t, err, movie.ErrMovieNotFound)
}

func TestMovieRepo_Delete_AlsoRemovesAssociatedShowtimes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	m := sampleMovie("movie-del-2")
	require.NoError(t, repo.Save(ctx, m))

	st := sampleShowtime("st-del-1", m.ID)
	require.NoError(t, repo.SaveShowtime(ctx, st))

	require.NoError(t, repo.Delete(ctx, m.ID))

	_, err := repo.FindShowtime(ctx, st.ID)
	assert.ErrorIs(t, err, movie.ErrShowtimeNotFound, "showtimes should be deleted with the movie")
}

// ── SaveShowtime + FindShowtime ───────────────────────────────────────────────

func TestMovieRepo_SaveShowtime_AndFindShowtime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	m := sampleMovie("movie-st-1")
	require.NoError(t, repo.Save(ctx, m))

	st := sampleShowtime("showtime-1", m.ID)
	require.NoError(t, repo.SaveShowtime(ctx, st))

	found, err := repo.FindShowtime(ctx, st.ID)
	require.NoError(t, err)
	assert.Equal(t, st.ID, found.ID)
	assert.Equal(t, st.MovieID, found.MovieID)
	assert.Equal(t, st.Hall, found.Hall)
	assert.Equal(t, st.Rows, found.Rows)
	assert.Equal(t, st.SeatsPerRow, found.SeatsPerRow)
	assert.Equal(t, st.Price.Cents(), found.Price.Cents())
}

func TestMovieRepo_FindShowtime_NotFound_ReturnsErrShowtimeNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	_, err := repo.FindShowtime(ctx, "ghost-showtime")
	assert.ErrorIs(t, err, movie.ErrShowtimeNotFound)
}

// ── DeleteShowtime ────────────────────────────────────────────────────────────

func TestMovieRepo_DeleteShowtime_RemovesShowtime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	m := sampleMovie("movie-dst-1")
	require.NoError(t, repo.Save(ctx, m))

	st := sampleShowtime("showtime-dst-1", m.ID)
	require.NoError(t, repo.SaveShowtime(ctx, st))
	require.NoError(t, repo.DeleteShowtime(ctx, st.ID))

	_, err := repo.FindShowtime(ctx, st.ID)
	assert.ErrorIs(t, err, movie.ErrShowtimeNotFound)
}

// ── FindAll with showtimes ────────────────────────────────────────────────────

func TestMovieRepo_FindAll_IncludesShowtimes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()

	m := sampleMovie("movie-fasi-1")
	require.NoError(t, repo.Save(ctx, m))
	require.NoError(t, repo.SaveShowtime(ctx, sampleShowtime("st-fasi-1", m.ID)))
	require.NoError(t, repo.SaveShowtime(ctx, sampleShowtime("st-fasi-2", m.ID)))

	movies, err := repo.FindAll(ctx)
	require.NoError(t, err)
	require.Len(t, movies, 1)
	assert.Len(t, movies[0].Showtimes, 2, "FindAll should eagerly load showtimes")
}
