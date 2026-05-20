package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
)

// Key schema:
//
//	seat:{showtimeID}:{seatID}  → sessionID           (NX TTL = held, no TTL = confirmed)
//	session:{sessionID}         → JSON(Session)        (TTL mirrors seat keys)

const (
	seatKeyFmt    = "seat:%s:%s"
	sessionKeyFmt = "session:%s"
)

// luaHoldSeats atomically holds N seats.
// KEYS   = seat keys for each seatID
// ARGV[1] = sessionID
// ARGV[2] = TTL in seconds
// ARGV[3] = session JSON
// ARGV[4] = session Redis key
const luaHoldSeats = `
local locked = {}
for i = 1, #KEYS do
    local ok = redis.call('SET', KEYS[i], ARGV[1], 'NX', 'EX', tonumber(ARGV[2]))
    if ok then
        table.insert(locked, KEYS[i])
    else
        for _, k in ipairs(locked) do redis.call('DEL', k) end
        return redis.error_reply('SEAT_TAKEN:' .. KEYS[i])
    end
end
redis.call('SET', ARGV[4], ARGV[3], 'EX', tonumber(ARGV[2]))
return 'OK'
`

// luaConfirm removes TTL from all seat keys + session key (persists the booking).
// KEYS[1]     = session Redis key
// KEYS[2..n]  = seat Redis keys
// ARGV[1]     = updated session JSON
const luaConfirm = `
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PERSIST', KEYS[1])
for i = 2, #KEYS do redis.call('PERSIST', KEYS[i]) end
return 'OK'
`

// luaRelease deletes all seat keys + session key (cancels the hold).
// KEYS = session key + seat keys
const luaRelease = `
for _, k in ipairs(KEYS) do redis.call('DEL', k) end
return 'OK'
`

type SeatLockRepository struct {
	rdb *redis.Client
}

func NewSeatLockRepository(rdb *redis.Client) *SeatLockRepository {
	return &SeatLockRepository{rdb: rdb}
}

func (r *SeatLockRepository) HoldSeats(ctx context.Context, req booking.HoldRequest) (booking.Session, error) {
	seatKeys := make([]string, len(req.SeatIDs))
	for i, id := range req.SeatIDs {
		seatKeys[i] = fmt.Sprintf(seatKeyFmt, req.ShowtimeID, id)
	}
	sessionKey := fmt.Sprintf(sessionKeyFmt, req.SessionID)

	session := booking.Session{
		ID:         req.SessionID,
		UserID:     req.UserID,
		ShowtimeID: req.ShowtimeID,
		MovieID:    req.MovieID,
		SeatIDs:    req.SeatIDs,
		Status:     booking.StatusHeld,
		ExpiresAt:  time.Now().Add(time.Duration(req.HoldTTL) * time.Second).Unix(),
	}
	sessionJSON, _ := json.Marshal(session)

	script := redis.NewScript(luaHoldSeats)
	err := script.Run(ctx, r.rdb, seatKeys,
		req.SessionID,
		req.HoldTTL,
		string(sessionJSON),
		sessionKey,
	).Err()

	if err != nil {
		if strings.HasPrefix(err.Error(), "SEAT_TAKEN:") {
			return booking.Session{}, booking.ErrSeatAlreadyHeld
		}
		return booking.Session{}, fmt.Errorf("hold seats lua: %w", err)
	}
	return session, nil
}

func (r *SeatLockRepository) GetSession(ctx context.Context, sessionID string) (booking.Session, error) {
	key := fmt.Sprintf(sessionKeyFmt, sessionID)
	val, err := r.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return booking.Session{}, booking.ErrSessionNotFound
	}
	if err != nil {
		return booking.Session{}, fmt.Errorf("get session: %w", err)
	}
	var session booking.Session
	if err := json.Unmarshal([]byte(val), &session); err != nil {
		return booking.Session{}, fmt.Errorf("parse session: %w", err)
	}
	return session, nil
}

func (r *SeatLockRepository) ConfirmSession(ctx context.Context, sessionID string) error {
	session, err := r.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.Status = booking.StatusConfirmed
	updatedJSON, _ := json.Marshal(session)

	sessionKey := fmt.Sprintf(sessionKeyFmt, sessionID)
	keys := make([]string, 0, len(session.SeatIDs)+1)
	keys = append(keys, sessionKey)
	for _, id := range session.SeatIDs {
		keys = append(keys, fmt.Sprintf(seatKeyFmt, session.ShowtimeID, id))
	}

	script := redis.NewScript(luaConfirm)
	return script.Run(ctx, r.rdb, keys, string(updatedJSON)).Err()
}

func (r *SeatLockRepository) ReleaseSession(ctx context.Context, sessionID string) error {
	session, err := r.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	sessionKey := fmt.Sprintf(sessionKeyFmt, sessionID)
	keys := make([]string, 0, len(session.SeatIDs)+1)
	keys = append(keys, sessionKey)
	for _, id := range session.SeatIDs {
		keys = append(keys, fmt.Sprintf(seatKeyFmt, session.ShowtimeID, id))
	}

	script := redis.NewScript(luaRelease)
	return script.Run(ctx, r.rdb, keys).Err()
}

// GetSeatStatuses returns real-time seat availability.
// It resolves HeldByMe by looking up the session owner for each held seat.
func (r *SeatLockRepository) GetSeatStatuses(ctx context.Context, showtimeID string, requestingUserID string) ([]booking.SeatStatus, error) {
	pattern := fmt.Sprintf(seatKeyFmt, showtimeID, "*")
	var statuses []booking.SeatStatus

	iter := r.rdb.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		seatKey := iter.Val()
		parts := strings.Split(seatKey, ":")
		seatID := parts[len(parts)-1]

		sessionID, err := r.rdb.Get(ctx, seatKey).Result()
		if err != nil {
			continue
		}

		ttl, _ := r.rdb.TTL(ctx, seatKey).Result()

		status := booking.SeatStatus{SeatID: seatID}
		if ttl < 0 {
			status.Status = string(booking.StatusConfirmed)
		} else {
			status.Status = string(booking.StatusHeld)
			remaining := int64(ttl.Seconds())
			status.ExpiresAt = &remaining

			if requestingUserID != "" {
				if session, sErr := r.GetSession(ctx, sessionID); sErr == nil {
					status.HeldByMe = session.UserID == requestingUserID
				}
			}
		}
		statuses = append(statuses, status)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("scan seat keys: %w", err)
	}
	return statuses, nil
}
