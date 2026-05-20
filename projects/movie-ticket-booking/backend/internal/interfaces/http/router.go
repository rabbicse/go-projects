package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
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

type RouterConfig struct {
	AllowedOrigins []string
	MaxSeats       int
}

func NewRouter(
	movieSvc *moviesvc.Service,
	bookSvc *bookingsvc.Service,
	cfg RouterConfig,
) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Logger())
	r.Use(middleware.CORS(cfg.AllowedOrigins))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	movieH := handler.NewMovieHandler(movieSvc)
	bookH := handler.NewBookingHandler(bookSvc, cfg.MaxSeats)
	adminH := handler.NewAdminHandler(movieSvc)

	api := r.Group("/api/v1")
	{
		// Swagger UI — open http://localhost:8080/api/v1/docs
		api.GET("/docs", func(c *gin.Context) {
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(swaggerUIHTML))
		})
		api.GET("/docs/swagger.json", func(c *gin.Context) {
			c.Data(http.StatusOK, "application/json", docs.SwaggerSpec)
		})

		// Movies & showtimes (read-only)
		api.GET("/movies", movieH.ListMovies)
		api.GET("/movies/:id", movieH.GetMovie)
		api.GET("/showtimes/:showtimeId", movieH.GetShowtime)

		// Booking flow
		api.GET("/showtimes/:showtimeId/seats", bookH.GetSeatMap)
		api.POST("/showtimes/:showtimeId/hold", bookH.HoldSeats)
		api.PUT("/sessions/:sessionId/confirm", bookH.ConfirmBooking)
		api.DELETE("/sessions/:sessionId", bookH.ReleaseBooking)

		// User history
		api.GET("/users/:userId/bookings", bookH.GetUserBookings)

		// Admin — HTTP Basic Auth (admin/admin)
		admin := api.Group("/admin", gin.BasicAuth(gin.Accounts{"admin": "admin"}))
		{
			admin.GET("/movies", adminH.ListMovies)
			admin.POST("/movies", adminH.CreateMovie)
			admin.POST("/movies/:movieId/showtimes", adminH.CreateShowtime)
		}
	}

	return r
}
