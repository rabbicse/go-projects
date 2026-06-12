package http

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	paymentsvc "github.com/rabbicse/movie-ticket-booking/internal/application/payment"
	showsvc "github.com/rabbicse/movie-ticket-booking/internal/application/show"
	theatersvc "github.com/rabbicse/movie-ticket-booking/internal/application/theater"
	"github.com/rabbicse/movie-ticket-booking/internal/docs"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/handler"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

const swaggerUIHTML = `<!DOCTYPE html>
<html>
<head>
  <title>Movie Ticket Booking — API Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/api/v1/docs/swagger.json",
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout"
    });
  </script>
</body>
</html>`

// RouterConfig holds all tunable options for the HTTP layer.
type RouterConfig struct {
	AllowedOrigins []string
	MaxSeats       int
	AdminUser      string
	AdminPassword  string

	// JWTAuth enables external RS256 token validation via JWKS (legacy / future OAuth2 path).
	// Ignored when JWTSecret is non-empty.
	JWTAuth gin.HandlerFunc

	// JWTSecret enables built-in HS256 auth. When non-empty, booking routes require a
	// valid Bearer token issued by AuthHandler. Takes precedence over JWTAuth.
	JWTSecret string
}

func NewRouter(
	movieSvc *moviesvc.Service,
	bookSvc *bookingsvc.Service,
	paySvc *paymentsvc.Service,
	authSvc *authapp.Service, // nil when JWT_SECRET is not set
	theaterSvc *theatersvc.Service, // nil when not wired
	showSvc *showsvc.Service,       // nil when not wired
	cfg RouterConfig,
) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestID())
	r.Use(middleware.Metrics())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.BodyLimit(5 << 20)) // 5 MB (covers JSON payloads and poster uploads)
	r.MaxMultipartMemory = 4 << 20       // 4 MB for multipart forms
	r.Use(middleware.Logger())
	r.Use(middleware.CORS(cfg.AllowedOrigins))

	r.Static("/uploads", "./uploads")
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	movieH := handler.NewMovieHandler(movieSvc)
	bookH := handler.NewBookingHandler(bookSvc, movieSvc, cfg.MaxSeats)
	payH := handler.NewPaymentHandler(paySvc)
	adminH := handler.NewAdminHandler(movieSvc, bookSvc)

	api := r.Group("/api/v1")
	{
		// Swagger UI
		api.GET("/docs", func(c *gin.Context) {
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(swaggerUIHTML))
		})
		api.GET("/docs/swagger.json", func(c *gin.Context) {
			c.Data(http.StatusOK, "application/json", docs.SwaggerSpec)
		})

		// ── Auth endpoints (always public) ────────────────────────────────────
		if authSvc != nil {
			authH := handler.NewAuthHandler(authSvc)
			auth := api.Group("/auth")
			{
				auth.POST("/register", authH.Register)
				auth.POST("/login", authH.Login)
				auth.POST("/refresh", authH.Refresh)
				auth.POST("/logout", authH.Logout)
				// Profile requires a valid token.
				auth.GET("/profile", middleware.RequireAuth(cfg.JWTSecret), authH.GetProfile)
			}
		}

		// ── Movies & showtimes (read-only, always public) ─────────────────────
		api.GET("/movies", movieH.ListMovies)
		api.GET("/movies/:id", movieH.GetMovie)
		api.GET("/showtimes/:showtimeId", movieH.GetShowtime)
		api.GET("/showtimes/:showtimeId/seats", bookH.GetSeatMap)

		// ── Booking flow (optional auth, backward-compatible) ─────────────────
		booking := api.Group("")
		switch {
		case cfg.JWTSecret != "":
			// Built-in HS256 auth — preferred when JWT_SECRET is configured.
			booking.Use(middleware.RequireAuth(cfg.JWTSecret))
		case cfg.JWTAuth != nil:
			// External JWKS/RS256 auth (future OAuth2/PKCE path).
			booking.Use(cfg.JWTAuth)
		}
		booking.POST("/showtimes/:showtimeId/hold",
			middleware.HoldRateLimit(10, time.Minute), bookH.HoldSeats)
		booking.POST("/sessions/:sessionId/pay", payH.Pay)
		booking.PUT("/sessions/:sessionId/confirm", bookH.ConfirmBooking)
		booking.DELETE("/sessions/:sessionId", bookH.ReleaseBooking)
		booking.GET("/users/:userId/bookings", bookH.GetUserBookings)

		// ── Admin ─────────────────────────────────────────────────────────────
		// JWT RequireRole("admin") when JWT_SECRET is configured; Basic Auth otherwise.
		// Both paths are kept so that curl/tooling with credentials still works in dev.
		var admin *gin.RouterGroup
		if cfg.JWTSecret != "" {
			admin = api.Group("/admin",
				middleware.RequireAuth(cfg.JWTSecret),
				middleware.RequireRole("admin"),
			)
		} else {
			admin = api.Group("/admin", gin.BasicAuth(gin.Accounts{cfg.AdminUser: cfg.AdminPassword}))
		}
		{
			admin.GET("/stats", adminH.GetStats)
			admin.GET("/movies", adminH.ListMovies)
			admin.POST("/movies", adminH.CreateMovie)
			admin.PUT("/movies/:movieId", adminH.UpdateMovie)
			admin.DELETE("/movies/:movieId", adminH.DeleteMovie)
			admin.PUT("/movies/:movieId/publish", adminH.PublishMovie)
			admin.PUT("/movies/:movieId/unpublish", adminH.UnpublishMovie)
			admin.POST("/movies/:movieId/poster", adminH.UploadPoster)
			admin.POST("/movies/:movieId/showtimes", adminH.CreateShowtime)
			admin.PUT("/movies/:movieId/showtimes/:showtimeId", adminH.UpdateShowtime)
			admin.DELETE("/movies/:movieId/showtimes/:showtimeId", adminH.DeleteShowtime)

			if theaterSvc != nil {
				theaterH := handler.NewTheaterHandler(theaterSvc)
				admin.GET("/theaters", theaterH.ListTheaters)
				admin.POST("/theaters", theaterH.CreateTheater)
				admin.GET("/theaters/:theaterId", theaterH.GetTheater)
				admin.PUT("/theaters/:theaterId", theaterH.UpdateTheater)
				admin.PUT("/theaters/:theaterId/disable", theaterH.DisableTheater)
				admin.GET("/theaters/:theaterId/screens", theaterH.ListScreens)
				admin.POST("/theaters/:theaterId/screens", theaterH.CreateScreen)
				admin.PUT("/theaters/:theaterId/screens/:screenId", theaterH.UpdateScreen)
				admin.PUT("/theaters/:theaterId/screens/:screenId/disable", theaterH.DisableScreen)
			}
			if showSvc != nil {
				showH := handler.NewShowHandler(showSvc)
				admin.GET("/shows", showH.ListShows)
				admin.POST("/shows", showH.CreateShow)
				admin.GET("/shows/:showId", showH.GetShow)
				admin.PUT("/shows/:showId", showH.UpdateShow)
				admin.PUT("/shows/:showId/cancel", showH.CancelShow)
			}
		}
	}

	return r
}
