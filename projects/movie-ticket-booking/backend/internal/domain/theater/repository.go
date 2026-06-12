package theater

import "context"

type Repository interface {
	FindAll(ctx context.Context) ([]Theater, error)
	FindByID(ctx context.Context, id string) (Theater, error)
	Save(ctx context.Context, t Theater) error
	Update(ctx context.Context, t Theater) error

	FindScreensByTheater(ctx context.Context, theaterID string) ([]Screen, error)
	FindScreenByID(ctx context.Context, id string) (Screen, error)
	SaveScreen(ctx context.Context, s Screen) error
	UpdateScreen(ctx context.Context, s Screen) error
}
