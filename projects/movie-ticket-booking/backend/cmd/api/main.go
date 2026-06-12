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

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	apievents "github.com/rabbicse/movie-ticket-booking/internal/application/events"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	paymentsvc "github.com/rabbicse/movie-ticket-booking/internal/application/payment"
	showsvc "github.com/rabbicse/movie-ticket-booking/internal/application/show"
	theatersvc "github.com/rabbicse/movie-ticket-booking/internal/application/theater"
	"github.com/rabbicse/movie-ticket-booking/internal/config"
	bookingdomain "github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/infrastructure/gateway"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
	"github.com/rabbicse/movie-ticket-booking/internal/infrastructure/seeder"
	ginhttp "github.com/rabbicse/movie-ticket-booking/internal/interfaces/http"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
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
	userRepo := mongoinfra.NewUserRepository(db)
	theaterRepo := mongoinfra.NewTheaterRepository(db)
	showRepo := mongoinfra.NewShowRepository(db)

	// Create indexes
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	must(movieRepo.EnsureIndexes(ctx), "ensure movie indexes")
	must(bookingRepo.EnsureIndexes(ctx), "ensure booking indexes")
	must(userRepo.EnsureIndexes(ctx), "ensure user indexes")
	must(theaterRepo.EnsureIndexes(ctx), "ensure theater indexes")
	must(showRepo.EnsureIndexes(ctx), "ensure show indexes")
	cancel()

	// Seed default data
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := seeder.Seed(seedCtx, movieRepo); err != nil {
		slog.Warn("movie seed failed", "error", err)
	}
	if err := seeder.SeedAdminUser(seedCtx, userRepo); err != nil {
		slog.Warn("admin seed failed", "error", err)
	}
	seedCancel()

	// --- Event dispatcher ---
	dispatcher := apievents.NewInProcess()
	logHandler := apievents.LogHandler()
	dispatcher.Register(bookingdomain.EventNameBookingCreated, logHandler)
	dispatcher.Register(bookingdomain.EventNameBookingConfirmed, logHandler)
	dispatcher.Register(bookingdomain.EventNameBookingReleased, logHandler)
	dispatcher.Register(bookingdomain.EventNameBookingExpired, logHandler)

	// --- Application services ---
	movieService := moviesvc.NewService(movieRepo)
	theaterService := theatersvc.NewService(theaterRepo)
	showService := showsvc.NewService(showRepo, movieRepo, theaterRepo)
	bookingService := bookingsvc.NewService(
		seatLockRepo,
		bookingRepo,
		movieRepo,
		dispatcher,
		cfg.Booking.MaxSeatsPerSession,
		cfg.Booking.HoldTTL,
	)
	paymentService := paymentsvc.NewService(gateway.NewMockPaymentGateway(), bookingService)

	// Auth service — wired only when JWT_SECRET is set.
	// Extension point: inject OAuth2/PKCE/MFA adapters here without touching other services.
	var authService *authapp.Service
	if cfg.Auth.JWTSecret != "" {
		refreshStore := redisinfra.NewRefreshTokenStore(redisClient)
		authService = authapp.NewService(userRepo, refreshStore, cfg.Auth.JWTSecret, cfg.Auth.RefreshTokenTTL)
		slog.Info("built-in HS256 auth enabled", "refresh_ttl", cfg.Auth.RefreshTokenTTL.String())
	} else {
		slog.Warn("JWT_SECRET not set — /auth endpoints disabled, booking routes are unauthenticated")
	}

	// --- HTTP server ---
	routerCfg := ginhttp.RouterConfig{
		AllowedOrigins: []string{"*"},
		MaxSeats:       cfg.Booking.MaxSeatsPerSession,
		AdminUser:      cfg.Admin.User,
		AdminPassword:  cfg.Admin.Password,
		JWTSecret:      cfg.Auth.JWTSecret,
	}
	slog.Info("booking config",
		"max_seats", cfg.Booking.MaxSeatsPerSession,
		"hold_ttl", cfg.Booking.HoldTTL.String(),
	)
	if cfg.Auth.JWKSEndpoint != "" {
		jwtMW := middleware.NewJWTMiddleware(cfg.Auth.JWKSEndpoint)
		routerCfg.JWTAuth = jwtMW.Handler()
		slog.Info("external JWKS auth enabled", "jwks_base", cfg.Auth.JWKSEndpoint)
	}

	router := ginhttp.NewRouter(movieService, bookingService, paymentService, authService, theaterService, showService, routerCfg)

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
