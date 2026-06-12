package show_test

import (
	"testing"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseShow() show.Show {
	now := time.Now().UTC()
	return show.Show{
		ID:        "show-1",
		MovieID:   "movie-1",
		ScreenID:  "screen-1",
		StartTime: now.Add(1 * time.Hour),
		EndTime:   now.Add(3 * time.Hour),
		Status:    show.ShowStatusScheduled,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestShow_Cancel_HappyPath(t *testing.T) {
	s := baseShow()
	err := s.Cancel()
	require.NoError(t, err)
	assert.Equal(t, show.ShowStatusCancelled, s.Status)
}

func TestShow_Cancel_AlreadyCancelled(t *testing.T) {
	s := baseShow()
	_ = s.Cancel()
	err := s.Cancel()
	assert.ErrorIs(t, err, show.ErrShowCancelled)
}

func TestShow_Overlaps(t *testing.T) {
	base := time.Now().UTC()
	s := show.Show{
		StartTime: base.Add(2 * time.Hour),
		EndTime:   base.Add(4 * time.Hour),
	}

	tests := []struct {
		name  string
		start time.Time
		end   time.Time
		want  bool
	}{
		{"exact match", base.Add(2 * time.Hour), base.Add(4 * time.Hour), true},
		{"overlaps at start", base.Add(1 * time.Hour), base.Add(3 * time.Hour), true},
		{"overlaps at end", base.Add(3 * time.Hour), base.Add(5 * time.Hour), true},
		{"fully contains", base.Add(1 * time.Hour), base.Add(5 * time.Hour), true},
		{"contained within", base.Add(2*time.Hour + 30*time.Minute), base.Add(3*time.Hour + 30*time.Minute), true},
		{"ends exactly at start", base.Add(1 * time.Hour), base.Add(2 * time.Hour), false},
		{"starts exactly at end", base.Add(4 * time.Hour), base.Add(5 * time.Hour), false},
		{"before", base, base.Add(1 * time.Hour), false},
		{"after", base.Add(5 * time.Hour), base.Add(6 * time.Hour), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.Overlaps(tc.start, tc.end))
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &show.ValidationError{Message: "end_time must be after start_time"}
	assert.Equal(t, "end_time must be after start_time", err.Error())
}
