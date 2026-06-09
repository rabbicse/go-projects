package redis

import (
	"context"
	"encoding/json"
	"errors"
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
// RC-02 fix: EXISTS guard prevents a silent success when the hold TTL fired between
// the checkout page load and the user clicking "Confirm Payment".
// KEYS[1]     = session Redis key
// KEYS[2..n]  = seat Redis keys
// ARGV[1]     = updated session JSON
const luaConfirm = `
if redis.call('EXISTS', KEYS[1]) == 0 then
    return redis.error_reply('SESSION_EXPIRED')
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PERSIST', KEYS[1])
for i = 2, #KEYS do redis.call('PERSIST', KEYS[i]) end
return 'OK'
`

// luaRelease deletes all seat keys + session key (cancels the hold).
// RC-01 fix: TTL guard prevents a concurrent release from deleting seats that were
// just confirmed. TTL == -1 means PERSIST was already called (seat is confirmed).
// KEYS = session key + seat keys
const luaRelease = `
local ttl = redis.call('TTL', KEYS[1])
if ttl == -1 then
    return 'ALREADY_CONFIRMED'
end
if ttl == -2 then
    return 'NOT_FOUND'
end
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
	if errors.Is(err, redis.Nil) {
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
	err = script.Run(ctx, r.rdb, keys, string(updatedJSON)).Err()
	if err != nil {
		if strings.Contains(err.Error(), "SESSION_EXPIRED") {
			return booking.ErrSessionExpired
		}
		return fmt.Errorf("confirm lua: %w", err)
	}
	return nil
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
	result, err := script.Run(ctx, r.rdb, keys).Text()
	if err != nil {
		return fmt.Errorf("release lua: %w", err)
	}
	switch result {
	case "ALREADY_CONFIRMED":
		// RC-01: release arrived after confirm — seats remain confirmed, this is correct.
		return booking.ErrInvalidStatusTransition
	case "NOT_FOUND":
		// Hold TTL fired between GetSession and ReleaseSession; seats already freed.
		return nil
	}
	return nil
}

// GetSeatStatuses returns real-time seat availability using two pipelines:
// one for seat keys (GET + TTL) and one for session keys (HeldByMe resolution).
// This replaces the previous per-seat serial GET+TTL calls (N+1 → 2 round trips).
func (r *SeatLockRepository) GetSeatStatuses(ctx context.Context, showtimeID string, requestingUserID string) ([]booking.SeatStatus, error) {
	// Step 1: collect seat keys via SCAN (non-blocking, hint 200 for typical hall size)
	pattern := fmt.Sprintf(seatKeyFmt, showtimeID, "*")
	var seatKeys []string
	iter := r.rdb.Scan(ctx, 0, pattern, 200).Iterator()
	for iter.Next(ctx) {
		seatKeys = append(seatKeys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("scan seat keys: %w", err)
	}
	if len(seatKeys) == 0 {
		return nil, nil
	}

	// Step 2: pipeline GET + TTL for all seat keys (1 round trip regardless of seat count)
	pipe := r.rdb.Pipeline()
	getCmds := make([]*redis.StringCmd, len(seatKeys))
	ttlCmds := make([]*redis.DurationCmd, len(seatKeys))
	for i, key := range seatKeys {
		getCmds[i] = pipe.Get(ctx, key)
		ttlCmds[i] = pipe.TTL(ctx, key)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("pipeline seat statuses: %w", err)
	}

	// Step 3: parse pipeline results; collect unique session IDs for held seats
	type seatEntry struct {
		seatID    string
		sessionID string
		ttl       time.Duration
	}
	entries := make([]seatEntry, 0, len(seatKeys))
	uniqueSessions := make(map[string]struct{})

	for i, key := range seatKeys {
		sessionID, err := getCmds[i].Result()
		if err != nil {
			continue // key expired between SCAN and pipeline exec
		}
		ttl, _ := ttlCmds[i].Result()
		parts := strings.Split(key, ":")
		seatID := parts[len(parts)-1]
		entries = append(entries, seatEntry{seatID: seatID, sessionID: sessionID, ttl: ttl})
		if ttl >= 0 && requestingUserID != "" {
			uniqueSessions[sessionID] = struct{}{}
		}
	}

	// Step 4: pipeline GET for unique session keys (1 round trip for HeldByMe resolution)
	sessionOwners := make(map[string]string) // sessionID → userID
	if len(uniqueSessions) > 0 {
		sessionPipe := r.rdb.Pipeline()
		sessionCmds := make(map[string]*redis.StringCmd, len(uniqueSessions))
		for sid := range uniqueSessions {
			sessionCmds[sid] = sessionPipe.Get(ctx, fmt.Sprintf(sessionKeyFmt, sid))
		}
		if _, err := sessionPipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("pipeline session owners: %w", err)
		}
		for sid, cmd := range sessionCmds {
			if val, err := cmd.Result(); err == nil {
				var s booking.Session
				if json.Unmarshal([]byte(val), &s) == nil {
					sessionOwners[sid] = s.UserID
				}
			}
		}
	}

	// Step 5: build result slice
	statuses := make([]booking.SeatStatus, 0, len(entries))
	for _, e := range entries {
		st := booking.SeatStatus{SeatID: e.seatID}
		if e.ttl < 0 {
			st.Status = string(booking.StatusConfirmed)
		} else {
			st.Status = string(booking.StatusHeld)
			remaining := int64(e.ttl.Seconds())
			st.ExpiresAt = &remaining
			if requestingUserID != "" {
				st.HeldByMe = sessionOwners[e.sessionID] == requestingUserID
			}
		}
		statuses = append(statuses, st)
	}
	return statuses, nil
}
