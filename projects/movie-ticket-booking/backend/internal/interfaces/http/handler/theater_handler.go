package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

type TheaterHandler struct {
	svc TheaterService
}

func NewTheaterHandler(svc TheaterService) *TheaterHandler {
	return &TheaterHandler{svc: svc}
}

// GET /api/v1/admin/theaters
func (h *TheaterHandler) ListTheaters(c *gin.Context) {
	theaters, err := h.svc.ListTheaters(c.Request.Context())
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	resp := make([]dto.TheaterResponse, len(theaters))
	for i, t := range theaters {
		resp[i] = dto.ToTheaterResponse(t)
	}
	c.JSON(http.StatusOK, resp)
}

// GET /api/v1/admin/theaters/:theaterId
func (h *TheaterHandler) GetTheater(c *gin.Context) {
	t, err := h.svc.GetTheater(c.Request.Context(), c.Param("theaterId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToTheaterResponse(t))
}

// POST /api/v1/admin/theaters
func (h *TheaterHandler) CreateTheater(c *gin.Context) {
	var req dto.CreateTheaterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	t := req.ToDomain()
	if err := h.svc.CreateTheater(c.Request.Context(), t); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	created, _ := h.svc.GetTheater(c.Request.Context(), t.ID)
	c.JSON(http.StatusCreated, dto.ToTheaterResponse(created))
}

// PUT /api/v1/admin/theaters/:theaterId
func (h *TheaterHandler) UpdateTheater(c *gin.Context) {
	var req dto.UpdateTheaterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	id := c.Param("theaterId")
	existing, err := h.svc.GetTheater(c.Request.Context(), id)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	t := theater.Theater{
		ID:        id,
		Name:      req.Name,
		Location:  req.Location,
		Status:    existing.Status,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: time.Now().UTC(),
	}
	if err := h.svc.UpdateTheater(c.Request.Context(), t); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	updated, _ := h.svc.GetTheater(c.Request.Context(), id)
	c.JSON(http.StatusOK, dto.ToTheaterResponse(updated))
}

// PUT /api/v1/admin/theaters/:theaterId/disable
func (h *TheaterHandler) DisableTheater(c *gin.Context) {
	t, err := h.svc.DisableTheater(c.Request.Context(), c.Param("theaterId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToTheaterResponse(t))
}

// GET /api/v1/admin/theaters/:theaterId/screens
func (h *TheaterHandler) ListScreens(c *gin.Context) {
	screens, err := h.svc.ListScreens(c.Request.Context(), c.Param("theaterId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	resp := make([]dto.ScreenResponse, len(screens))
	for i, s := range screens {
		resp[i] = dto.ToScreenResponse(s)
	}
	c.JSON(http.StatusOK, resp)
}

// POST /api/v1/admin/theaters/:theaterId/screens
func (h *TheaterHandler) CreateScreen(c *gin.Context) {
	var req dto.CreateScreenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	sc := req.ToDomain(c.Param("theaterId"))
	if err := h.svc.CreateScreen(c.Request.Context(), sc); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	created, _ := h.svc.GetScreen(c.Request.Context(), sc.ID)
	c.JSON(http.StatusCreated, dto.ToScreenResponse(created))
}

// PUT /api/v1/admin/theaters/:theaterId/screens/:screenId
func (h *TheaterHandler) UpdateScreen(c *gin.Context) {
	var req dto.UpdateScreenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}
	id := c.Param("screenId")
	existing, err := h.svc.GetScreen(c.Request.Context(), id)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	sc := req.ToDomain(id, c.Param("theaterId"), existing)
	if err := h.svc.UpdateScreen(c.Request.Context(), sc); err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	updated, _ := h.svc.GetScreen(c.Request.Context(), id)
	c.JSON(http.StatusOK, dto.ToScreenResponse(updated))
}

// PUT /api/v1/admin/theaters/:theaterId/screens/:screenId/disable
func (h *TheaterHandler) DisableScreen(c *gin.Context) {
	sc, err := h.svc.DisableScreen(c.Request.Context(), c.Param("screenId"))
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}
	c.JSON(http.StatusOK, dto.ToScreenResponse(sc))
}
