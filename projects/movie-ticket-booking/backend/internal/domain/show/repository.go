package show

import (
	"context"
	"time"
)

type Repository interface {
	FindAll(ctx context.Context) ([]Show, error)
	FindByID(ctx context.Context, id string) (Show, error)
	FindByScreenAndTimeRange(ctx context.Context, screenID string, start, end time.Time) ([]Show, error)
	Save(ctx context.Context, s Show) error
	Update(ctx context.Context, s Show) error
}
