package show

import (
	"context"
	"fmt"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
)

type Service struct {
	repo        show.Repository
	movieRepo   movie.Repository
	theaterRepo theater.Repository
}

func NewService(repo show.Repository, movieRepo movie.Repository, theaterRepo theater.Repository) *Service {
	return &Service{repo: repo, movieRepo: movieRepo, theaterRepo: theaterRepo}
}

func (s *Service) ListShows(ctx context.Context) ([]show.Show, error) {
	shows, err := s.repo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list shows: %w", err)
	}
	return shows, nil
}

func (s *Service) GetShow(ctx context.Context, id string) (show.Show, error) {
	sh, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return show.Show{}, fmt.Errorf("get show %s: %w", id, err)
	}
	return sh, nil
}

func (s *Service) CreateShow(ctx context.Context, sh show.Show) error {
	if !sh.EndTime.After(sh.StartTime) {
		return &show.ValidationError{Message: "end_time must be after start_time"}
	}
	if _, err := s.movieRepo.FindByID(ctx, sh.MovieID); err != nil {
		return fmt.Errorf("create show: movie %s: %w", sh.MovieID, err)
	}
	screen, err := s.theaterRepo.FindScreenByID(ctx, sh.ScreenID)
	if err != nil {
		return fmt.Errorf("create show: screen %s: %w", sh.ScreenID, err)
	}
	if screen.Status == theater.ScreenStatusDisabled {
		return &show.ValidationError{Message: "cannot schedule a show on a disabled screen"}
	}
	if err := s.checkOverlap(ctx, sh.ScreenID, sh.StartTime, sh.EndTime, ""); err != nil {
		return err
	}
	if err := s.repo.Save(ctx, sh); err != nil {
		return fmt.Errorf("create show: %w", err)
	}
	return nil
}

// UpdateShow updates a show's schedule and references. The caller is responsible for
// preserving Status and CreatedAt from the existing record.
func (s *Service) UpdateShow(ctx context.Context, sh show.Show) error {
	if !sh.EndTime.After(sh.StartTime) {
		return &show.ValidationError{Message: "end_time must be after start_time"}
	}
	if _, err := s.movieRepo.FindByID(ctx, sh.MovieID); err != nil {
		return fmt.Errorf("update show: movie %s: %w", sh.MovieID, err)
	}
	screen, err := s.theaterRepo.FindScreenByID(ctx, sh.ScreenID)
	if err != nil {
		return fmt.Errorf("update show: screen %s: %w", sh.ScreenID, err)
	}
	if screen.Status == theater.ScreenStatusDisabled {
		return &show.ValidationError{Message: "cannot schedule a show on a disabled screen"}
	}
	if err := s.checkOverlap(ctx, sh.ScreenID, sh.StartTime, sh.EndTime, sh.ID); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, sh); err != nil {
		return fmt.Errorf("update show: %w", err)
	}
	return nil
}

func (s *Service) CancelShow(ctx context.Context, id string) (show.Show, error) {
	sh, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return show.Show{}, fmt.Errorf("cancel show: %w", err)
	}
	if err := sh.Cancel(); err != nil {
		return show.Show{}, err
	}
	if err := s.repo.Update(ctx, sh); err != nil {
		return show.Show{}, fmt.Errorf("cancel show: %w", err)
	}
	return sh, nil
}

func (s *Service) checkOverlap(ctx context.Context, screenID string, start, end time.Time, excludeID string) error {
	conflicts, err := s.repo.FindByScreenAndTimeRange(ctx, screenID, start, end)
	if err != nil {
		return fmt.Errorf("check overlap: %w", err)
	}
	for _, c := range conflicts {
		if c.ID != excludeID {
			return show.ErrShowConflict
		}
	}
	return nil
}
