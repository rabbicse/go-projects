package dto

type PayRequest struct {
	UserID      string `json:"user_id"`
	AmountCents int64  `json:"amount_cents" binding:"required,min=1"`
	Currency    string `json:"currency"     binding:"required"`
	CardNumber  string `json:"card_number"  binding:"required"`
	Expiry      string `json:"expiry"       binding:"required"`
	CVV         string `json:"cvv"          binding:"required"`
}

type PayResponse struct {
	PaymentID string          `json:"payment_id"`
	Status    string          `json:"status"`
	Booking   BookingResponse `json:"booking"`
}
