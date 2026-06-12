package dto

import (
	"fmt"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
)

// ── Theater ───────────────────────────────────────────────────────────────────

type CreateTheaterRequest struct {
	ID       string `json:"id"       binding:"required"`
	Name     string `json:"name"     binding:"required"`
	Location string `json:"location" binding:"required"`
}

type UpdateTheaterRequest struct {
	Name     string `json:"name"     binding:"required"`
	Location string `json:"location" binding:"required"`
}

type TheaterResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Location  string `json:"location"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (r CreateTheaterRequest) ToDomain() theater.Theater {
	now := time.Now().UTC()
	return theater.Theater{
		ID:        r.ID,
		Name:      r.Name,
		Location:  r.Location,
		Status:    theater.TheaterStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func ToTheaterResponse(t theater.Theater) TheaterResponse {
	return TheaterResponse{
		ID:        t.ID,
		Name:      t.Name,
		Location:  t.Location,
		Status:    string(t.Status),
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
		UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
	}
}

// ── Screen ────────────────────────────────────────────────────────────────────

// RowCategoryInput maps a single row label (e.g. "A") to a seat category.
type RowCategoryInput struct {
	Row      string `json:"row"      binding:"required"`
	Category string `json:"category" binding:"required,oneof=standard premium vip"`
}

type CreateScreenRequest struct {
	ID            string             `json:"id"             binding:"required"`
	Name          string             `json:"name"           binding:"required"`
	RowsCount     int                `json:"rows_count"     binding:"required,gt=0,lte=26"`
	SeatsPerRow   int                `json:"seats_per_row"  binding:"required,gt=0,lte=50"`
	RowCategories []RowCategoryInput `json:"row_categories"`
}

type UpdateScreenRequest struct {
	Name          string             `json:"name"          binding:"required"`
	RowsCount     int                `json:"rows_count"    binding:"required,gt=0,lte=26"`
	SeatsPerRow   int                `json:"seats_per_row" binding:"required,gt=0,lte=50"`
	RowCategories []RowCategoryInput `json:"row_categories"`
}

type SeatResponse struct {
	ID       string `json:"id"`
	Row      string `json:"row"`
	Number   int    `json:"number"`
	Category string `json:"category"`
}

type ScreenResponse struct {
	ID        string         `json:"id"`
	TheaterID string         `json:"theater_id"`
	Name      string         `json:"name"`
	Capacity  int            `json:"capacity"`
	Seats     []SeatResponse `json:"seats"`
	Status    string         `json:"status"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

func (r CreateScreenRequest) ToDomain(theaterID string) theater.Screen {
	now := time.Now().UTC()
	return theater.Screen{
		ID:        r.ID,
		TheaterID: theaterID,
		Name:      r.Name,
		Capacity:  r.RowsCount * r.SeatsPerRow,
		Seats:     GenerateSeats(r.ID, r.RowsCount, r.SeatsPerRow, r.RowCategories),
		Status:    theater.ScreenStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (r UpdateScreenRequest) ToDomain(id, theaterID string, existing theater.Screen) theater.Screen {
	return theater.Screen{
		ID:        id,
		TheaterID: theaterID,
		Name:      r.Name,
		Capacity:  r.RowsCount * r.SeatsPerRow,
		Seats:     GenerateSeats(id, r.RowsCount, r.SeatsPerRow, r.RowCategories),
		Status:    existing.Status,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now().UTC(),
	}
}

func ToScreenResponse(s theater.Screen) ScreenResponse {
	seats := make([]SeatResponse, len(s.Seats))
	for i, seat := range s.Seats {
		seats[i] = SeatResponse{
			ID:       seat.ID,
			Row:      seat.Row,
			Number:   seat.Number,
			Category: string(seat.Category),
		}
	}
	return ScreenResponse{
		ID:        s.ID,
		TheaterID: s.TheaterID,
		Name:      s.Name,
		Capacity:  s.Capacity,
		Seats:     seats,
		Status:    string(s.Status),
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		UpdatedAt: s.UpdatedAt.Format(time.RFC3339),
	}
}

// GenerateSeats builds seat value objects from a screen layout.
// Rows are labeled A-Z; seats within each row are numbered 1–N.
// Rows not listed in rowCats default to the "standard" category.
func GenerateSeats(screenID string, rowsCount, seatsPerRow int, rowCats []RowCategoryInput) []theater.Seat {
	catMap := make(map[string]theater.SeatCategory, len(rowCats))
	for _, rc := range rowCats {
		catMap[rc.Row] = theater.SeatCategory(rc.Category)
	}
	seats := make([]theater.Seat, 0, rowsCount*seatsPerRow)
	for r := 0; r < rowsCount; r++ {
		row := string(rune('A' + r))
		cat := theater.SeatCategoryStandard
		if c, ok := catMap[row]; ok {
			cat = c
		}
		for n := 1; n <= seatsPerRow; n++ {
			seats = append(seats, theater.Seat{
				ID:       fmt.Sprintf("%s-%s%d", screenID, row, n),
				Row:      row,
				Number:   n,
				Category: cat,
			})
		}
	}
	return seats
}
