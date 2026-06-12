package movie_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func validMovie() movie.Movie {
	return movie.Movie{
		ID:          "test-movie",
		Title:       "Test Film",
		Genre:       []string{"Action"},
		Rating:      7.5,
		DurationMin: 120,
	}
}

func futureShowtime(id, hall string, startOffset, endOffset time.Duration) movie.Showtime {
	now := time.Now()
	return movie.Showtime{
		ID:          id,
		MovieID:     "test-movie",
		Hall:        hall,
		StartTime:   now.Add(startOffset),
		EndTime:     now.Add(endOffset),
		Rows:        8,
		SeatsPerRow: 10,
		Price:       shared.USD(1500),
	}
}

// ── Validate ──────────────────────────────────────────────────────────────────

func TestValidate_ValidMovie_ReturnsNil(t *testing.T) {
	m := validMovie()
	assert.NoError(t, m.Validate())
}

func TestValidate_EmptyTitle_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.Title = ""
	err := m.Validate()
	require.Error(t, err)
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "title is required")
}

func TestValidate_WhitespaceOnlyTitle_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.Title = "   "
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "title is required")
}

func TestValidate_NoGenre_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.Genre = nil
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "at least one genre is required")
}

func TestValidate_EmptyGenreSlice_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.Genre = []string{}
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "at least one genre is required")
}

func TestValidate_DurationZero_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.DurationMin = 0
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "duration must be at least 1 minute")
}

func TestValidate_DurationNegative_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.DurationMin = -1
	err := m.Validate()
	require.Error(t, err)
}

func TestValidate_RatingBelowZero_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.Rating = -0.1
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "rating must be between 0 and 10")
}

func TestValidate_RatingAbove10_ReturnsValidationError(t *testing.T) {
	m := validMovie()
	m.Rating = 10.1
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Contains(t, ve.Messages, "rating must be between 0 and 10")
}

func TestValidate_RatingBoundary0_ReturnsNil(t *testing.T) {
	m := validMovie()
	m.Rating = 0
	assert.NoError(t, m.Validate())
}

func TestValidate_RatingBoundary10_ReturnsNil(t *testing.T) {
	m := validMovie()
	m.Rating = 10
	assert.NoError(t, m.Validate())
}

func TestValidate_MultipleViolations_AccumulatesMessages(t *testing.T) {
	m := movie.Movie{} // zero value: title, genre, duration all invalid
	err := m.Validate()
	var ve *movie.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.GreaterOrEqual(t, len(ve.Messages), 3, "should collect all violations")
}

// ── Publish ───────────────────────────────────────────────────────────────────

func TestPublish_ValidMovie_SetsPublishedTrue(t *testing.T) {
	m := validMovie()
	require.NoError(t, m.Publish())
	assert.True(t, m.Published)
}

func TestPublish_ValidMovie_UpdatesUpdatedAt(t *testing.T) {
	m := validMovie()
	before := time.Now().UTC().Add(-time.Second)
	require.NoError(t, m.Publish())
	assert.True(t, m.UpdatedAt.After(before))
}

func TestPublish_InvalidMovie_ReturnsValidationError_StaysUnpublished(t *testing.T) {
	m := validMovie()
	m.Title = ""
	err := m.Publish()
	require.Error(t, err)
	assert.False(t, m.Published, "movie must not become published on validation failure")
}

func TestPublish_AlreadyPublished_CanPublishAgain(t *testing.T) {
	m := validMovie()
	m.Published = true
	assert.NoError(t, m.Publish()) // idempotent on valid movie
	assert.True(t, m.Published)
}

// ── Unpublish ─────────────────────────────────────────────────────────────────

func TestUnpublish_SetsFalse(t *testing.T) {
	m := validMovie()
	m.Published = true
	m.Unpublish()
	assert.False(t, m.Published)
}

func TestUnpublish_UpdatesUpdatedAt(t *testing.T) {
	m := validMovie()
	m.Published = true
	before := time.Now().UTC().Add(-time.Second)
	m.Unpublish()
	assert.True(t, m.UpdatedAt.After(before))
}

func TestUnpublish_AlreadyUnpublished_IsIdempotent(t *testing.T) {
	m := validMovie()
	m.Published = false
	m.Unpublish() // should not panic
	assert.False(t, m.Published)
}

// ── AddShowtime ───────────────────────────────────────────────────────────────

func TestAddShowtime_NoConflict_Succeeds(t *testing.T) {
	m := validMovie()
	st := futureShowtime("st-1", "Hall A", 2*time.Hour, 4*time.Hour)
	require.NoError(t, m.AddShowtime(st))
	assert.Len(t, m.Showtimes, 1)
}

func TestAddShowtime_WrongMovieID_ReturnsError(t *testing.T) {
	m := validMovie()
	st := futureShowtime("st-1", "Hall A", 2*time.Hour, 4*time.Hour)
	st.MovieID = "different-movie"
	assert.Error(t, m.AddShowtime(st))
	assert.Empty(t, m.Showtimes)
}

func TestAddShowtime_SameHall_OverlappingTimes_ReturnsError(t *testing.T) {
	m := validMovie()
	st1 := futureShowtime("st-1", "Hall A", 2*time.Hour, 4*time.Hour)
	require.NoError(t, m.AddShowtime(st1))

	// Overlapping: starts before st1 ends.
	st2 := futureShowtime("st-2", "Hall A", 3*time.Hour, 5*time.Hour)
	assert.Error(t, m.AddShowtime(st2), "overlapping showtimes in same hall must be rejected")
}

func TestAddShowtime_SameHall_NonOverlapping_Succeeds(t *testing.T) {
	m := validMovie()
	st1 := futureShowtime("st-1", "Hall A", 1*time.Hour, 3*time.Hour)
	st2 := futureShowtime("st-2", "Hall A", 4*time.Hour, 6*time.Hour) // gap between
	require.NoError(t, m.AddShowtime(st1))
	require.NoError(t, m.AddShowtime(st2))
	assert.Len(t, m.Showtimes, 2)
}

func TestAddShowtime_DifferentHalls_OverlappingTimes_Succeeds(t *testing.T) {
	m := validMovie()
	st1 := futureShowtime("st-1", "Hall A", 2*time.Hour, 4*time.Hour)
	st2 := futureShowtime("st-2", "Hall B", 2*time.Hour, 4*time.Hour) // different hall, same time
	require.NoError(t, m.AddShowtime(st1))
	require.NoError(t, m.AddShowtime(st2))
	assert.Len(t, m.Showtimes, 2)
}

// ── TotalSeats ────────────────────────────────────────────────────────────────

func TestTotalSeats_NoShowtimes_ReturnsZero(t *testing.T) {
	m := validMovie()
	assert.Equal(t, 0, m.TotalSeats())
}

func TestTotalSeats_MultipleShowtimes_SumsCorrectly(t *testing.T) {
	m := validMovie()
	m.Showtimes = []movie.Showtime{
		{Rows: 8, SeatsPerRow: 10},  // 80
		{Rows: 6, SeatsPerRow: 8},   // 48
		{Rows: 10, SeatsPerRow: 12}, // 120
	}
	assert.Equal(t, 248, m.TotalSeats())
}

// ── ValidationError ───────────────────────────────────────────────────────────

func TestValidationError_Error_JoinsMessages(t *testing.T) {
	ve := &movie.ValidationError{Messages: []string{"a is required", "b is invalid"}}
	assert.Equal(t, "a is required; b is invalid", ve.Error())
}
