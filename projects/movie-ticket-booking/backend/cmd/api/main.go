package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/config"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
	"github.com/rabbicse/movie-ticket-booking/internal/infrastructure/seeder"
	ginhttp "github.com/rabbicse/movie-ticket-booking/internal/interfaces/http"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	must(err, "load config")

	gin.SetMode(cfg.Server.Mode)

	// --- Infrastructure ---
	redisClient, err := redisinfra.NewClient(cfg.Redis)
	must(err, "connect redis")

	mongoClient, err := mongoinfra.NewClient(cfg.MongoDB)
	must(err, "connect mongodb")
	defer func() { _ = mongoClient.Disconnect(context.Background()) }()

	db := mongoinfra.Database(mongoClient, cfg.MongoDB)

	movieRepo := mongoinfra.NewMovieRepository(db)
	bookingRepo := mongoinfra.NewBookingRepository(db)
	seatLockRepo := redisinfra.NewSeatLockRepository(redisClient)

	// Create indexes
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	must(movieRepo.EnsureIndexes(ctx), "ensure movie indexes")
	must(bookingRepo.EnsureIndexes(ctx), "ensure booking indexes")
	cancel()

	// Seed default data
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := seeder.Seed(seedCtx, movieRepo); err != nil {
		slog.Warn("seed failed", "error", err)
	}
	seedCancel()

	// --- Application services ---
	movieService := moviesvc.NewService(movieRepo)
	bookingService := bookingsvc.NewService(
		seatLockRepo,
		bookingRepo,
		movieRepo,
		cfg.Booking.MaxSeatsPerSession,
		cfg.Booking.HoldTTL,
	)

	// --- HTTP server ---
	router := ginhttp.NewRouter(movieService, bookingService, ginhttp.RouterConfig{
		AllowedOrigins: []string{"*"},
		MaxSeats:       cfg.Booking.MaxSeatsPerSession,
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		slog.Info("server started", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
	slog.Info("server stopped")
}

func must(err error, msg string) {
	if err != nil {
		slog.Error(msg, "error", err)
		os.Exit(1)
	}
}
