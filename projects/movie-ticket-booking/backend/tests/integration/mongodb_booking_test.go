package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
)

func startMongoDB(t *testing.T) *mongo.Database {
	t.Helper()
	ctx := context.Background()
	container, err := mongodb.Run(ctx, "mongo:7")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	client, err := mongo.Connect(options.Client().ApplyURI(connStr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(ctx) })

	return client.Database("test_" + uuid.New().String()[:8])
}

func makeTestBooking(userID, sessionID, showtimeID string, status booking.Status) booking.Booking {
	seats := []booking.Seat{{ID: "A1", Row: "A", Number: 1}}
	b, _ := booking.New(sessionID, userID, showtimeID, "movie-1", seats, shared.USD(1500), 10*time.Minute)
	b.ID = uuid.New().String()
	b.Status = status
	if status == booking.StatusConfirmed {
		now := time.Now()
		b.ConfirmedAt = &now
	}
	return b
}

func TestBookingRepository_SaveAndFind(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewBookingRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	b := makeTestBooking("user-1", uuid.New().String(), "show-1", booking.StatusHeld)
	require.NoError(t, repo.Save(ctx, b))

	found, err := repo.FindByID(ctx, b.ID)
	require.NoError(t, err)
	assert.Equal(t, b.ID, found.ID)
	assert.Equal(t, booking.StatusHeld, found.Status)
	assert.Equal(t, "A1", found.Seats[0].ID)
}

func TestBookingRepository_FindBySessionID(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewBookingRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	sessionID := uuid.New().String()
	b := makeTestBooking("user-2", sessionID, "show-2", booking.StatusHeld)
	require.NoError(t, repo.Save(ctx, b))

	found, err := repo.FindBySessionID(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, sessionID, found.SessionID)
}

func TestBookingRepository_Update(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewBookingRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	b := makeTestBooking("user-3", uuid.New().String(), "show-3", booking.StatusHeld)
	require.NoError(t, repo.Save(ctx, b))

	b.Status = booking.StatusConfirmed
	now := time.Now()
	b.ConfirmedAt = &now
	require.NoError(t, repo.Update(ctx, b))

	found, err := repo.FindByID(ctx, b.ID)
	require.NoError(t, err)
	assert.Equal(t, booking.StatusConfirmed, found.Status)
	assert.NotNil(t, found.ConfirmedAt)
}

func TestBookingRepository_FindByUserID(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewBookingRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	userID := "user-find-" + uuid.New().String()
	for i := range 3 {
		b := makeTestBooking(userID, uuid.New().String(), "show-"+string(rune('A'+i)), booking.StatusConfirmed)
		require.NoError(t, repo.Save(ctx, b))
	}
	// different user's booking
	require.NoError(t, repo.Save(ctx, makeTestBooking("other-user", uuid.New().String(), "show-X", booking.StatusHeld)))

	results, err := repo.FindByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, results, 3)
}

func TestBookingRepository_NotFound(t *testing.T) {
	db := startMongoDB(t)
	repo := mongoinfra.NewBookingRepository(db)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "non-existent-id")
	assert.ErrorIs(t, err, booking.ErrBookingNotFound)
}
