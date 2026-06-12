package theater_test

import (
	"testing"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
	"github.com/stretchr/testify/assert"
)

func baseTheater() theater.Theater {
	now := time.Now().UTC()
	return theater.Theater{
		ID:        "t1",
		Name:      "Grand Cinema",
		Location:  "Downtown",
		Status:    theater.TheaterStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestTheater_Disable(t *testing.T) {
	th := baseTheater()
	before := th.UpdatedAt
	th.Disable()

	assert.Equal(t, theater.TheaterStatusDisabled, th.Status)
	assert.True(t, th.UpdatedAt.After(before) || th.UpdatedAt.Equal(before))
}

func TestTheater_Disable_Idempotent(t *testing.T) {
	th := baseTheater()
	th.Disable()
	th.Disable()
	assert.Equal(t, theater.TheaterStatusDisabled, th.Status)
}

func TestScreen_Disable(t *testing.T) {
	sc := theater.Screen{
		ID:        "s1",
		TheaterID: "t1",
		Name:      "Screen 1",
		Status:    theater.ScreenStatusActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	sc.Disable()
	assert.Equal(t, theater.ScreenStatusDisabled, sc.Status)
}

func TestSeatCategory_Constants(t *testing.T) {
	assert.Equal(t, theater.SeatCategory("standard"), theater.SeatCategoryStandard)
	assert.Equal(t, theater.SeatCategory("premium"), theater.SeatCategoryPremium)
	assert.Equal(t, theater.SeatCategory("vip"), theater.SeatCategoryVIP)
}

func TestValidationError_Error(t *testing.T) {
	err := &theater.ValidationError{Message: "name is required"}
	assert.Equal(t, "name is required", err.Error())
}
