package theater

import (
	"context"
	"fmt"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
)

type Service struct {
	repo theater.Repository
}

func NewService(repo theater.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListTheaters(ctx context.Context) ([]theater.Theater, error) {
	ts, err := s.repo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list theaters: %w", err)
	}
	return ts, nil
}

func (s *Service) GetTheater(ctx context.Context, id string) (theater.Theater, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return theater.Theater{}, fmt.Errorf("get theater %s: %w", id, err)
	}
	return t, nil
}

func (s *Service) CreateTheater(ctx context.Context, t theater.Theater) error {
	if err := s.repo.Save(ctx, t); err != nil {
		return fmt.Errorf("create theater: %w", err)
	}
	return nil
}

func (s *Service) UpdateTheater(ctx context.Context, t theater.Theater) error {
	if err := s.repo.Update(ctx, t); err != nil {
		return fmt.Errorf("update theater: %w", err)
	}
	return nil
}

func (s *Service) DisableTheater(ctx context.Context, id string) (theater.Theater, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return theater.Theater{}, fmt.Errorf("disable theater: %w", err)
	}
	t.Disable()
	if err := s.repo.Update(ctx, t); err != nil {
		return theater.Theater{}, fmt.Errorf("disable theater: %w", err)
	}
	return t, nil
}

func (s *Service) ListScreens(ctx context.Context, theaterID string) ([]theater.Screen, error) {
	if _, err := s.repo.FindByID(ctx, theaterID); err != nil {
		return nil, fmt.Errorf("list screens: %w", err)
	}
	screens, err := s.repo.FindScreensByTheater(ctx, theaterID)
	if err != nil {
		return nil, fmt.Errorf("list screens: %w", err)
	}
	return screens, nil
}

func (s *Service) GetScreen(ctx context.Context, id string) (theater.Screen, error) {
	sc, err := s.repo.FindScreenByID(ctx, id)
	if err != nil {
		return theater.Screen{}, fmt.Errorf("get screen %s: %w", id, err)
	}
	return sc, nil
}

func (s *Service) CreateScreen(ctx context.Context, sc theater.Screen) error {
	if _, err := s.repo.FindByID(ctx, sc.TheaterID); err != nil {
		return fmt.Errorf("create screen: theater %s: %w", sc.TheaterID, err)
	}
	if err := s.repo.SaveScreen(ctx, sc); err != nil {
		return fmt.Errorf("create screen: %w", err)
	}
	return nil
}

func (s *Service) UpdateScreen(ctx context.Context, sc theater.Screen) error {
	if err := s.repo.UpdateScreen(ctx, sc); err != nil {
		return fmt.Errorf("update screen: %w", err)
	}
	return nil
}

func (s *Service) DisableScreen(ctx context.Context, id string) (theater.Screen, error) {
	sc, err := s.repo.FindScreenByID(ctx, id)
	if err != nil {
		return theater.Screen{}, fmt.Errorf("disable screen: %w", err)
	}
	sc.Disable()
	if err := s.repo.UpdateScreen(ctx, sc); err != nil {
		return theater.Screen{}, fmt.Errorf("disable screen: %w", err)
	}
	return sc, nil
}
