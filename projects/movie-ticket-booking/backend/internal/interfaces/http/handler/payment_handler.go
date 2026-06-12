package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	paymentsvc "github.com/rabbicse/movie-ticket-booking/internal/application/payment"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/payment"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/dto"
)

type PaymentHandler struct {
	svc *paymentsvc.Service
}

func NewPaymentHandler(svc *paymentsvc.Service) *PaymentHandler {
	return &PaymentHandler{svc: svc}
}

// Pay handles POST /sessions/:sessionId/pay.
// Charges the provided card via the mock gateway; on success confirms the booking atomically.
func (h *PaymentHandler) Pay(c *gin.Context) {
	var req dto.PayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}

	userID := resolveUserID(c, req.UserID)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, apierr.New("UNAUTHENTICATED", "user_id required"))
		return
	}

	result, err := h.svc.Pay(
		c.Request.Context(),
		c.Param("sessionId"),
		userID,
		req.AmountCents,
		req.Currency,
		payment.CardDetails{Number: req.CardNumber, Expiry: req.Expiry, CVV: req.CVV},
	)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, dto.PayResponse{
		PaymentID: result.Payment.ID,
		Status:    string(result.Payment.Status),
		Booking:   dto.ToBookingResponse(result.Booking),
	})
}
