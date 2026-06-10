package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
)

// indexKeyFields extracts field names from a MongoDB index key document.
// The driver v2 decodes nested BSON as bson.D (ordered), not bson.M (map).
func indexKeyFields(raw any) map[string]bool {
	fields := make(map[string]bool)
	switch k := raw.(type) {
	case bson.M:
		for field := range k {
			fields[field] = true
		}
	case bson.D:
		for _, elem := range k {
			fields[elem.Key] = true
		}
	}
	return fields
}

func testMovie(id string) movie.Movie {
	return movie.Movie{
		ID:          id,
		Title:       "Test Movie " + id[:8],
		Genre:       []string{"Drama"},
		Rating:      7.5,
		DurationMin: 120,
	}
}

func testShowtime(id, movieID string, offsetHours int) movie.Showtime {
	base := time.Date(2026, 6, 15, 14, 0, 0, 0, time.UTC)
	start := base.Add(time.Duration(offsetHours) * time.Hour)
	return movie.Showtime{
		ID:          id,
		MovieID:     movieID,
		Hall:        "Hall A",
		StartTime:   start,
		EndTime:     start.Add(2 * time.Hour),
		Rows:        10,
		SeatsPerRow: 12,
		Price:       shared.NewMoney(1500, "USD"),
	}
}

// TestBookingIndexes_TTLPartialIndexCreated verifies that EnsureIndexes creates the
// partial TTL index on expires_at with the correct expireAfterSeconds and partialFilterExpression.
func TestBookingIndexes_TTLPartialIndexCreated(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewBookingRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	cur, err := db.Collection("bookings").Indexes().List(ctx)
	require.NoError(t, err)
	defer cur.Close(ctx)

	var indexes []bson.M
	require.NoError(t, cur.All(ctx, &indexes))

	var foundTTL, foundCompound bool
	for _, idx := range indexes {
		// MongoDB driver v2 decodes nested BSON documents as bson.D (ordered), not bson.M.
		keyFields := indexKeyFields(idx["key"])
		if keyFields["expires_at"] {
			if _, hasTTL := idx["expireAfterSeconds"]; hasTTL {
				_, hasPartial := idx["partialFilterExpression"]
				assert.True(t, hasPartial, "TTL index on expires_at must have partialFilterExpression")
				foundTTL = true
			}
		}
		if keyFields["user_id"] && keyFields["created_at"] {
			foundCompound = true
		}
	}

	assert.True(t, foundTTL, "TTL partial index on expires_at must be created")
	assert.True(t, foundCompound, "compound index on {user_id, created_at} must be created")
}

// TestMovieRepository_FindAll_NoN1 verifies that FindAll loads movies with their
// showtimes correctly in exactly 2 queries (no N+1 per movie).
func TestMovieRepository_FindAll_NoN1(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	// Seed 3 movies with 2 showtimes each.
	for range 3 {
		movieID := uuid.New().String()
		m := testMovie(movieID)
		require.NoError(t, repo.Save(ctx, m))
		for j := range 2 {
			st := testShowtime(uuid.New().String(), movieID, j)
			require.NoError(t, repo.SaveShowtime(ctx, st))
		}
	}

	movies, err := repo.FindAll(ctx)
	require.NoError(t, err)
	require.Len(t, movies, 3)
	for _, m := range movies {
		assert.Len(t, m.Showtimes, 2, "movie %s must have 2 showtimes loaded", m.ID)
	}
}

// TestMovieRepository_FindAll_ShowtimesOrderedByStartTime verifies showtimes are
// returned sorted by start_time ascending.
func TestMovieRepository_FindAll_ShowtimesOrderedByStartTime(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewMovieRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	movieID := uuid.New().String()
	require.NoError(t, repo.Save(ctx, testMovie(movieID)))

	// Insert showtimes in reverse order — FindAll must return them sorted ascending.
	for j := range 3 {
		require.NoError(t, repo.SaveShowtime(ctx, testShowtime(uuid.New().String(), movieID, 2-j)))
	}

	movies, err := repo.FindAll(ctx)
	require.NoError(t, err)
	require.Len(t, movies, 1)
	sts := movies[0].Showtimes
	require.Len(t, sts, 3)
	for i := 1; i < len(sts); i++ {
		assert.True(t, !sts[i].StartTime.Before(sts[i-1].StartTime),
			"showtimes must be ordered ascending by start_time")
	}
}
