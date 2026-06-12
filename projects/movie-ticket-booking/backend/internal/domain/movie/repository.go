package movie

import "context"

type Repository interface {
	FindAll(ctx context.Context) ([]Movie, error)
	FindByID(ctx context.Context, id string) (Movie, error)
	FindShowtime(ctx context.Context, showtimeID string) (Showtime, error)
	Save(ctx context.Context, m Movie) error
	SaveShowtime(ctx context.Context, s Showtime) error
	UpsertMany(ctx context.Context, movies []Movie) error
	Update(ctx context.Context, m Movie) error
	Delete(ctx context.Context, id string) error
	DeleteShowtime(ctx context.Context, showtimeID string) error
}
