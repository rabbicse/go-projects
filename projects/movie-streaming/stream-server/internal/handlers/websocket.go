package handlers

import (
	"magicstream/internal/websocket"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
)

// WebSocketHandler handles WebSocket connections
func WebSocketHandler(c *fiber.Ctx) error {
	// Upgrade to WebSocket connection
	if websocket.IsWebSocketUpgrade(c) {
		c.Locals("allowed", true)
		return c.Next()
	}

	return fiber.ErrUpgradeRequired
}

// WebSocketConnection handles individual WebSocket connections
var WebSocketConnection = websocket.New(func(conn *websocket.Conn) {
	client := &websocket.Client{
		Hub:  websocket.GetHub(),
		Conn: conn,
		Send: make(chan []byte, 256),
	}

	client.Hub.Register <- client

	// Start reading and writing messages
	go client.WritePump()
	client.ReadPump()
})

// BroadcastMessage sends a message to all connected clients
func BroadcastMessage(c *fiber.Ctx) error {
	type Message struct {
		Type    string      `json:"type"`
		Payload interface{} `json:"payload"`
	}

	var msg Message
	if err := c.BodyParser(&msg); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, "Invalid message format", err)
	}

	websocket.GetHub().Broadcast <- msg

	return utils.SuccessResponse(c, "Message broadcasted successfully", nil)
}
