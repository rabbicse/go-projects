package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

const bookingsCollection = "bookings"

type seatDoc struct {
	ID     string `bson:"id"`
	Row    string `bson:"row"`
	Number int    `bson:"number"`
}

type bookingDoc struct {
	ID          string    `bson:"_id"`
	SessionID   string    `bson:"session_id"`
	UserID      string    `bson:"user_id"`
	ShowtimeID  string    `bson:"showtime_id"`
	MovieID     string    `bson:"movie_id"`
	Seats       []seatDoc `bson:"seats"`
	Status      string    `bson:"status"`
	PriceCents  int64     `bson:"price_cents"`
	Currency    string    `bson:"currency"`
	CreatedAt   time.Time `bson:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at"`
	ExpiresAt   time.Time `bson:"expires_at"`
	ConfirmedAt *time.Time `bson:"confirmed_at,omitempty"`
}

type BookingRepository struct {
	db *mongo.Database
}

func NewBookingRepository(db *mongo.Database) *BookingRepository {
	return &BookingRepository{db: db}
}

func (r *BookingRepository) EnsureIndexes(ctx context.Context) error {
	coll := r.db.Collection(bookingsCollection)
	_, err := coll.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "session_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "showtime_id", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
	})
	return err
}

func (r *BookingRepository) Save(ctx context.Context, b booking.Booking) error {
	doc := fromBooking(b)
	_, err := r.db.Collection(bookingsCollection).InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("save booking: %w", err)
	}
	return nil
}

func (r *BookingRepository) Update(ctx context.Context, b booking.Booking) error {
	doc := fromBooking(b)
	filter := bson.M{"_id": b.ID}
	opts := options.Replace().SetUpsert(false)
	_, err := r.db.Collection(bookingsCollection).ReplaceOne(ctx, filter, doc, opts)
	if err != nil {
		return fmt.Errorf("update booking: %w", err)
	}
	return nil
}

func (r *BookingRepository) FindByID(ctx context.Context, id string) (booking.Booking, error) {
	var doc bookingDoc
	err := r.db.Collection(bookingsCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return booking.Booking{}, booking.ErrBookingNotFound
	}
	if err != nil {
		return booking.Booking{}, fmt.Errorf("find booking by id: %w", err)
	}
	return toBooking(doc), nil
}

func (r *BookingRepository) FindBySessionID(ctx context.Context, sessionID string) (booking.Booking, error) {
	var doc bookingDoc
	err := r.db.Collection(bookingsCollection).FindOne(ctx, bson.M{"session_id": sessionID}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return booking.Booking{}, booking.ErrBookingNotFound
	}
	if err != nil {
		return booking.Booking{}, fmt.Errorf("find booking by session: %w", err)
	}
	return toBooking(doc), nil
}

func (r *BookingRepository) FindByUserID(ctx context.Context, userID string) ([]booking.Booking, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cur, err := r.db.Collection(bookingsCollection).Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		return nil, fmt.Errorf("find bookings by user: %w", err)
	}
	defer cur.Close(ctx)
	return decodeBookings(ctx, cur)
}

func (r *BookingRepository) FindByShowtime(ctx context.Context, showtimeID string) ([]booking.Booking, error) {
	cur, err := r.db.Collection(bookingsCollection).Find(ctx, bson.M{"showtime_id": showtimeID})
	if err != nil {
		return nil, fmt.Errorf("find bookings by showtime: %w", err)
	}
	defer cur.Close(ctx)
	return decodeBookings(ctx, cur)
}

func decodeBookings(ctx context.Context, cur *mongo.Cursor) ([]booking.Booking, error) {
	var docs []bookingDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode bookings: %w", err)
	}
	result := make([]booking.Booking, len(docs))
	for i, d := range docs {
		result[i] = toBooking(d)
	}
	return result, nil
}

func toBooking(d bookingDoc) booking.Booking {
	seats := make([]booking.Seat, len(d.Seats))
	for i, s := range d.Seats {
		seats[i] = booking.Seat{ID: s.ID, Row: s.Row, Number: s.Number}
	}
	return booking.Booking{
		ID:          d.ID,
		SessionID:   d.SessionID,
		UserID:      d.UserID,
		ShowtimeID:  d.ShowtimeID,
		MovieID:     d.MovieID,
		Seats:       seats,
		Status:      booking.Status(d.Status),
		TotalPrice:  shared.NewMoney(d.PriceCents, d.Currency),
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
		ExpiresAt:   d.ExpiresAt,
		ConfirmedAt: d.ConfirmedAt,
	}
}

func fromBooking(b booking.Booking) bookingDoc {
	seats := make([]seatDoc, len(b.Seats))
	for i, s := range b.Seats {
		seats[i] = seatDoc{ID: s.ID, Row: s.Row, Number: s.Number}
	}
	return bookingDoc{
		ID:          b.ID,
		SessionID:   b.SessionID,
		UserID:      b.UserID,
		ShowtimeID:  b.ShowtimeID,
		MovieID:     b.MovieID,
		Seats:       seats,
		Status:      string(b.Status),
		PriceCents:  b.TotalPrice.Cents(),
		Currency:    b.TotalPrice.Currency(),
		CreatedAt:   b.CreatedAt,
		UpdatedAt:   b.UpdatedAt,
		ExpiresAt:   b.ExpiresAt,
		ConfirmedAt: b.ConfirmedAt,
	}
}
