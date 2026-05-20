package seeder

import (
	"context"
	"log/slog"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

// Seed inserts default movies and showtimes if the collection is empty.
func Seed(ctx context.Context, repo movie.Repository) error {
	existing, err := repo.FindAll(ctx)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		slog.Info("seed skipped: movies already exist", "count", len(existing))
		return nil
	}

	now := time.Now().UTC().Truncate(time.Hour)

	movies := []movie.Movie{
		{
			ID:          "dune-part-two",
			Title:       "Dune: Part Two",
			Genre:       []string{"Sci-Fi", "Adventure"},
			Rating:      8.5,
			PosterURL:   "https://image.tmdb.org/t/p/w500/1pdfLvkbY9ohJlCjQH2CZjjYVvJ.jpg",
			Description: "Paul Atreides unites with the Fremen while on a warpath of revenge.",
			DurationMin: 166,
			Showtimes: []movie.Showtime{
				{ID: "dune2-hall1-1", MovieID: "dune-part-two", Hall: "Hall A", StartTime: now.Add(2 * time.Hour), EndTime: now.Add(2*time.Hour + 166*time.Minute), Rows: 8, SeatsPerRow: 10, Price: shared.USD(1500)},
				{ID: "dune2-hall1-2", MovieID: "dune-part-two", Hall: "Hall A", StartTime: now.Add(26 * time.Hour), EndTime: now.Add(26*time.Hour + 166*time.Minute), Rows: 8, SeatsPerRow: 10, Price: shared.USD(1500)},
				{ID: "dune2-hall2-1", MovieID: "dune-part-two", Hall: "Hall B", StartTime: now.Add(5 * time.Hour), EndTime: now.Add(5*time.Hour + 166*time.Minute), Rows: 6, SeatsPerRow: 8, Price: shared.USD(1200)},
			},
		},
		{
			ID:          "oppenheimer",
			Title:       "Oppenheimer",
			Genre:       []string{"Biography", "Drama", "History"},
			Rating:      8.9,
			PosterURL:   "https://image.tmdb.org/t/p/w500/8Gxv8gSFCU0XGDykEGv7zR1n2ua.jpg",
			Description: "The story of J. Robert Oppenheimer's role in the development of the atomic bomb.",
			DurationMin: 180,
			Showtimes: []movie.Showtime{
				{ID: "oppen-hall2-1", MovieID: "oppenheimer", Hall: "Hall B", StartTime: now.Add(3 * time.Hour), EndTime: now.Add(3*time.Hour + 180*time.Minute), Rows: 6, SeatsPerRow: 8, Price: shared.USD(1400)},
				{ID: "oppen-hall3-1", MovieID: "oppenheimer", Hall: "Hall C", StartTime: now.Add(7 * time.Hour), EndTime: now.Add(7*time.Hour + 180*time.Minute), Rows: 10, SeatsPerRow: 12, Price: shared.USD(1600)},
			},
		},
		{
			ID:          "inception",
			Title:       "Inception",
			Genre:       []string{"Sci-Fi", "Action", "Thriller"},
			Rating:      8.8,
			PosterURL:   "https://image.tmdb.org/t/p/w500/oYuLEt3zVCKq57qu2F8dT7NIa6f.jpg",
			Description: "A thief who steals corporate secrets through dream-sharing technology.",
			DurationMin: 148,
			Showtimes: []movie.Showtime{
				{ID: "inception-hall1-1", MovieID: "inception", Hall: "Hall A", StartTime: now.Add(1 * time.Hour), EndTime: now.Add(1*time.Hour + 148*time.Minute), Rows: 8, SeatsPerRow: 10, Price: shared.USD(1000)},
				{ID: "inception-hall3-1", MovieID: "inception", Hall: "Hall C", StartTime: now.Add(4 * time.Hour), EndTime: now.Add(4*time.Hour + 148*time.Minute), Rows: 10, SeatsPerRow: 12, Price: shared.USD(1100)},
			},
		},
		{
			ID:          "the-batman",
			Title:       "The Batman",
			Genre:       []string{"Action", "Crime", "Drama"},
			Rating:      7.8,
			PosterURL:   "https://image.tmdb.org/t/p/w500/74xTEgt7R36Fpooo50r9T25onhq.jpg",
			Description: "Batman ventures into Gotham City's underworld when a sadistic killer leaves behind cryptic clues.",
			DurationMin: 176,
			Showtimes: []movie.Showtime{
				{ID: "batman-hall2-1", MovieID: "the-batman", Hall: "Hall B", StartTime: now.Add(6 * time.Hour), EndTime: now.Add(6*time.Hour + 176*time.Minute), Rows: 6, SeatsPerRow: 8, Price: shared.USD(1300)},
				{ID: "batman-hall1-1", MovieID: "the-batman", Hall: "Hall A", StartTime: now.Add(30 * time.Hour), EndTime: now.Add(30*time.Hour + 176*time.Minute), Rows: 8, SeatsPerRow: 10, Price: shared.USD(1300)},
			},
		},
		{
			ID:          "interstellar",
			Title:       "Interstellar",
			Genre:       []string{"Sci-Fi", "Adventure", "Drama"},
			Rating:      8.6,
			PosterURL:   "https://image.tmdb.org/t/p/w500/gEU2QniE6E77NI6lCU6MxlNBvIx.jpg",
			Description: "A team of explorers travel through a wormhole in space in an attempt to ensure humanity's survival.",
			DurationMin: 169,
			Showtimes: []movie.Showtime{
				{ID: "inter-hall3-1", MovieID: "interstellar", Hall: "Hall C", StartTime: now.Add(8 * time.Hour), EndTime: now.Add(8*time.Hour + 169*time.Minute), Rows: 10, SeatsPerRow: 12, Price: shared.USD(1100)},
				{ID: "inter-hall2-1", MovieID: "interstellar", Hall: "Hall B", StartTime: now.Add(32 * time.Hour), EndTime: now.Add(32*time.Hour + 169*time.Minute), Rows: 6, SeatsPerRow: 8, Price: shared.USD(1100)},
			},
		},
	}

	if err := repo.UpsertMany(ctx, movies); err != nil {
		return err
	}
	slog.Info("seed complete", "movies", len(movies))
	return nil
}
