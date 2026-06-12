package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
)

const showsCollection = "shows"

type showDoc struct {
	ID        string          `bson:"_id"`
	MovieID   string          `bson:"movie_id"`
	ScreenID  string          `bson:"screen_id"`
	StartTime time.Time       `bson:"start_time"`
	EndTime   time.Time       `bson:"end_time"`
	Status    show.ShowStatus `bson:"status"`
	CreatedAt time.Time       `bson:"created_at"`
	UpdatedAt time.Time       `bson:"updated_at"`
}

type ShowRepository struct {
	db *mongo.Database
}

func NewShowRepository(db *mongo.Database) *ShowRepository {
	return &ShowRepository{db: db}
}

func (r *ShowRepository) EnsureIndexes(ctx context.Context) error {
	// Compound index covering the overlap query: screen_id + status + time range.
	_, err := r.db.Collection(showsCollection).Indexes().CreateOne(ctx,
		mongo.IndexModel{
			Keys: bson.D{
				{Key: "screen_id", Value: 1},
				{Key: "status", Value: 1},
				{Key: "start_time", Value: 1},
				{Key: "end_time", Value: 1},
			},
		},
	)
	return err
}

func (r *ShowRepository) FindAll(ctx context.Context) ([]show.Show, error) {
	cur, err := r.db.Collection(showsCollection).Find(ctx, bson.D{},
		options.Find().SetSort(bson.D{{Key: "start_time", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find shows: %w", err)
	}
	defer cur.Close(ctx)

	var docs []showDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode shows: %w", err)
	}
	if len(docs) == 0 {
		return nil, nil
	}
	result := make([]show.Show, len(docs))
	for i, d := range docs {
		result[i] = toShow(d)
	}
	return result, nil
}

func (r *ShowRepository) FindByID(ctx context.Context, id string) (show.Show, error) {
	var doc showDoc
	err := r.db.Collection(showsCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return show.Show{}, show.ErrShowNotFound
	}
	if err != nil {
		return show.Show{}, fmt.Errorf("find show: %w", err)
	}
	return toShow(doc), nil
}

func (r *ShowRepository) FindByScreenAndTimeRange(ctx context.Context, screenID string, start, end time.Time) ([]show.Show, error) {
	filter := bson.M{
		"screen_id": screenID,
		"status":    show.ShowStatusScheduled,
		"start_time": bson.M{"$lt": end},
		"end_time":   bson.M{"$gt": start},
	}
	cur, err := r.db.Collection(showsCollection).Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("find overlapping shows: %w", err)
	}
	defer cur.Close(ctx)

	var docs []showDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode overlapping shows: %w", err)
	}
	result := make([]show.Show, len(docs))
	for i, d := range docs {
		result[i] = toShow(d)
	}
	return result, nil
}

func (r *ShowRepository) Save(ctx context.Context, s show.Show) error {
	doc := fromShow(s)
	opts := options.Replace().SetUpsert(true)
	_, err := r.db.Collection(showsCollection).ReplaceOne(ctx, bson.M{"_id": s.ID}, doc, opts)
	return err
}

func (r *ShowRepository) Update(ctx context.Context, s show.Show) error {
	doc := fromShow(s)
	res, err := r.db.Collection(showsCollection).ReplaceOne(ctx, bson.M{"_id": s.ID}, doc)
	if err != nil {
		return fmt.Errorf("update show: %w", err)
	}
	if res.MatchedCount == 0 {
		return show.ErrShowNotFound
	}
	return nil
}

// ── Mapping helpers ───────────────────────────────────────────────────────────

func toShow(d showDoc) show.Show {
	return show.Show{
		ID:        d.ID,
		MovieID:   d.MovieID,
		ScreenID:  d.ScreenID,
		StartTime: d.StartTime,
		EndTime:   d.EndTime,
		Status:    d.Status,
		CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt,
	}
}

func fromShow(s show.Show) showDoc {
	return showDoc{
		ID:        s.ID,
		MovieID:   s.MovieID,
		ScreenID:  s.ScreenID,
		StartTime: s.StartTime,
		EndTime:   s.EndTime,
		Status:    s.Status,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}
