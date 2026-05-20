package movie

import (
	"context"
	"fmt"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
)

type Service struct {
	repo movie.Repository
}

func NewService(repo movie.Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListMovies(ctx context.Context) ([]movie.Movie, error) {
	movies, err := s.repo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list movies: %w", err)
	}
	return movies, nil
}

func (s *Service) GetMovie(ctx context.Context, id string) (movie.Movie, error) {
	m, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return movie.Movie{}, fmt.Errorf("get movie %s: %w", id, err)
	}
	return m, nil
}

func (s *Service) GetShowtime(ctx context.Context, showtimeID string) (movie.Showtime, error) {
	st, err := s.repo.FindShowtime(ctx, showtimeID)
	if err != nil {
		return movie.Showtime{}, fmt.Errorf("get showtime %s: %w", showtimeID, err)
	}
	return st, nil
}

func (s *Service) CreateMovie(ctx context.Context, m movie.Movie) error {
	if err := s.repo.Save(ctx, m); err != nil {
		return fmt.Errorf("create movie: %w", err)
	}
	return nil
}

func (s *Service) CreateShowtime(ctx context.Context, st movie.Showtime) error {
	// Verify movie exists first
	if _, err := s.repo.FindByID(ctx, st.MovieID); err != nil {
		return fmt.Errorf("movie %s not found: %w", st.MovieID, err)
	}
	if err := s.repo.SaveShowtime(ctx, st); err != nil {
		return fmt.Errorf("create showtime: %w", err)
	}
	return nil
}
