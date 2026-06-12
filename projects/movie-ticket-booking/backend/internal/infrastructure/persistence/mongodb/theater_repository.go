package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
)

const (
	theatersCollection = "theaters"
	screensCollection  = "screens"
)

type theaterDoc struct {
	ID        string                `bson:"_id"`
	Name      string                `bson:"name"`
	Location  string                `bson:"location"`
	Status    theater.TheaterStatus `bson:"status"`
	CreatedAt time.Time             `bson:"created_at"`
	UpdatedAt time.Time             `bson:"updated_at"`
}

type screenDoc struct {
	ID        string               `bson:"_id"`
	TheaterID string               `bson:"theater_id"`
	Name      string               `bson:"name"`
	Capacity  int                  `bson:"capacity"`
	Seats     []theaterSeatDoc            `bson:"seats"`
	Status    theater.ScreenStatus `bson:"status"`
	CreatedAt time.Time            `bson:"created_at"`
	UpdatedAt time.Time            `bson:"updated_at"`
}

type theaterSeatDoc struct {
	ID       string               `bson:"_id"`
	Row      string               `bson:"row"`
	Number   int                  `bson:"number"`
	Category theater.SeatCategory `bson:"category"`
}

type TheaterRepository struct {
	db *mongo.Database
}

func NewTheaterRepository(db *mongo.Database) *TheaterRepository {
	return &TheaterRepository{db: db}
}

func (r *TheaterRepository) EnsureIndexes(ctx context.Context) error {
	_, err := r.db.Collection(screensCollection).Indexes().CreateOne(ctx,
		mongo.IndexModel{Keys: bson.D{{Key: "theater_id", Value: 1}}},
	)
	return err
}

func (r *TheaterRepository) FindAll(ctx context.Context) ([]theater.Theater, error) {
	cur, err := r.db.Collection(theatersCollection).Find(ctx, bson.D{},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find theaters: %w", err)
	}
	defer cur.Close(ctx)

	var docs []theaterDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode theaters: %w", err)
	}
	if len(docs) == 0 {
		return nil, nil
	}
	result := make([]theater.Theater, len(docs))
	for i, d := range docs {
		result[i] = toTheater(d)
	}
	return result, nil
}

func (r *TheaterRepository) FindByID(ctx context.Context, id string) (theater.Theater, error) {
	var doc theaterDoc
	err := r.db.Collection(theatersCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return theater.Theater{}, theater.ErrTheaterNotFound
	}
	if err != nil {
		return theater.Theater{}, fmt.Errorf("find theater: %w", err)
	}
	return toTheater(doc), nil
}

func (r *TheaterRepository) Save(ctx context.Context, t theater.Theater) error {
	doc := fromTheater(t)
	opts := options.Replace().SetUpsert(true)
	_, err := r.db.Collection(theatersCollection).ReplaceOne(ctx, bson.M{"_id": t.ID}, doc, opts)
	return err
}

func (r *TheaterRepository) Update(ctx context.Context, t theater.Theater) error {
	doc := fromTheater(t)
	res, err := r.db.Collection(theatersCollection).ReplaceOne(ctx, bson.M{"_id": t.ID}, doc)
	if err != nil {
		return fmt.Errorf("update theater: %w", err)
	}
	if res.MatchedCount == 0 {
		return theater.ErrTheaterNotFound
	}
	return nil
}

func (r *TheaterRepository) FindScreensByTheater(ctx context.Context, theaterID string) ([]theater.Screen, error) {
	cur, err := r.db.Collection(screensCollection).Find(ctx,
		bson.M{"theater_id": theaterID},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find screens: %w", err)
	}
	defer cur.Close(ctx)

	var docs []screenDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode screens: %w", err)
	}
	if len(docs) == 0 {
		return nil, nil
	}
	result := make([]theater.Screen, len(docs))
	for i, d := range docs {
		result[i] = toScreen(d)
	}
	return result, nil
}

func (r *TheaterRepository) FindScreenByID(ctx context.Context, id string) (theater.Screen, error) {
	var doc screenDoc
	err := r.db.Collection(screensCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return theater.Screen{}, theater.ErrScreenNotFound
	}
	if err != nil {
		return theater.Screen{}, fmt.Errorf("find screen: %w", err)
	}
	return toScreen(doc), nil
}

func (r *TheaterRepository) SaveScreen(ctx context.Context, s theater.Screen) error {
	doc := fromScreen(s)
	opts := options.Replace().SetUpsert(true)
	_, err := r.db.Collection(screensCollection).ReplaceOne(ctx, bson.M{"_id": s.ID}, doc, opts)
	return err
}

func (r *TheaterRepository) UpdateScreen(ctx context.Context, s theater.Screen) error {
	doc := fromScreen(s)
	res, err := r.db.Collection(screensCollection).ReplaceOne(ctx, bson.M{"_id": s.ID}, doc)
	if err != nil {
		return fmt.Errorf("update screen: %w", err)
	}
	if res.MatchedCount == 0 {
		return theater.ErrScreenNotFound
	}
	return nil
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

func toTheater(d theaterDoc) theater.Theater {
	return theater.Theater{
		ID:        d.ID,
		Name:      d.Name,
		Location:  d.Location,
		Status:    d.Status,
		CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt,
	}
}

func fromTheater(t theater.Theater) theaterDoc {
	return theaterDoc{
		ID:        t.ID,
		Name:      t.Name,
		Location:  t.Location,
		Status:    t.Status,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

func toScreen(d screenDoc) theater.Screen {
	seats := make([]theater.Seat, len(d.Seats))
	for i, s := range d.Seats {
		seats[i] = theater.Seat{
			ID:       s.ID,
			Row:      s.Row,
			Number:   s.Number,
			Category: s.Category,
		}
	}
	return theater.Screen{
		ID:        d.ID,
		TheaterID: d.TheaterID,
		Name:      d.Name,
		Capacity:  d.Capacity,
		Seats:     seats,
		Status:    d.Status,
		CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt,
	}
}

func fromScreen(s theater.Screen) screenDoc {
	seats := make([]theaterSeatDoc, len(s.Seats))
	for i, seat := range s.Seats {
		seats[i] = theaterSeatDoc{
			ID:       seat.ID,
			Row:      seat.Row,
			Number:   seat.Number,
			Category: seat.Category,
		}
	}
	return screenDoc{
		ID:        s.ID,
		TheaterID: s.TheaterID,
		Name:      s.Name,
		Capacity:  s.Capacity,
		Seats:     seats,
		Status:    s.Status,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}
