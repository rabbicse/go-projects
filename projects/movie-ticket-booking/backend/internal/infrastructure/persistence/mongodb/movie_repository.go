package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

const (
	moviesCollection    = "movies"
	showtimesCollection = "showtimes"
)

// movieDoc is the MongoDB representation of a Movie.
type movieDoc struct {
	ID          string   `bson:"_id"`
	Title       string   `bson:"title"`
	Genre       []string `bson:"genre"`
	Rating      float64  `bson:"rating"`
	PosterURL   string   `bson:"poster_url"`
	Description string   `bson:"description"`
	DurationMin int      `bson:"duration_min"`
}

// showtimeDoc is the MongoDB representation of a Showtime.
type showtimeDoc struct {
	ID          string    `bson:"_id"`
	MovieID     string    `bson:"movie_id"`
	Hall        string    `bson:"hall"`
	StartTime   time.Time `bson:"start_time"`
	EndTime     time.Time `bson:"end_time"`
	Rows        int       `bson:"rows"`
	SeatsPerRow int       `bson:"seats_per_row"`
	PriceCents  int64     `bson:"price_cents"`
	Currency    string    `bson:"currency"`
}

type MovieRepository struct {
	db *mongo.Database
}

func NewMovieRepository(db *mongo.Database) *MovieRepository {
	return &MovieRepository{db: db}
}

func (r *MovieRepository) EnsureIndexes(ctx context.Context) error {
	_, err := r.db.Collection(showtimesCollection).Indexes().CreateOne(ctx,
		mongo.IndexModel{Keys: bson.D{{Key: "movie_id", Value: 1}}},
	)
	return err
}

func (r *MovieRepository) FindAll(ctx context.Context) ([]movie.Movie, error) {
	cur, err := r.db.Collection(moviesCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("find movies: %w", err)
	}
	defer cur.Close(ctx)

	var docs []movieDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode movies: %w", err)
	}

	movies := make([]movie.Movie, len(docs))
	for i, d := range docs {
		movies[i] = toMovie(d)
		showtimes, _ := r.findShowtimesForMovie(ctx, d.ID)
		movies[i].Showtimes = showtimes
	}
	return movies, nil
}

func (r *MovieRepository) FindByID(ctx context.Context, id string) (movie.Movie, error) {
	var doc movieDoc
	err := r.db.Collection(moviesCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return movie.Movie{}, fmt.Errorf("movie %s not found", id)
	}
	if err != nil {
		return movie.Movie{}, fmt.Errorf("find movie: %w", err)
	}
	m := toMovie(doc)
	m.Showtimes, _ = r.findShowtimesForMovie(ctx, id)
	return m, nil
}

func (r *MovieRepository) FindShowtime(ctx context.Context, showtimeID string) (movie.Showtime, error) {
	var doc showtimeDoc
	err := r.db.Collection(showtimesCollection).FindOne(ctx, bson.M{"_id": showtimeID}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return movie.Showtime{}, fmt.Errorf("showtime %s not found", showtimeID)
	}
	if err != nil {
		return movie.Showtime{}, fmt.Errorf("find showtime: %w", err)
	}
	return toShowtime(doc), nil
}

func (r *MovieRepository) Save(ctx context.Context, m movie.Movie) error {
	doc := fromMovie(m)
	opts := options.Replace().SetUpsert(true)
	_, err := r.db.Collection(moviesCollection).ReplaceOne(ctx, bson.M{"_id": m.ID}, doc, opts)
	return err
}

func (r *MovieRepository) SaveShowtime(ctx context.Context, s movie.Showtime) error {
	doc := fromShowtime(s)
	opts := options.Replace().SetUpsert(true)
	_, err := r.db.Collection(showtimesCollection).ReplaceOne(ctx, bson.M{"_id": s.ID}, doc, opts)
	return err
}

func (r *MovieRepository) UpsertMany(ctx context.Context, movies []movie.Movie) error {
	for _, m := range movies {
		if err := r.Save(ctx, m); err != nil {
			return err
		}
		for _, st := range m.Showtimes {
			if err := r.SaveShowtime(ctx, st); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *MovieRepository) findShowtimesForMovie(ctx context.Context, movieID string) ([]movie.Showtime, error) {
	cur, err := r.db.Collection(showtimesCollection).Find(ctx, bson.M{"movie_id": movieID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var docs []showtimeDoc
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	result := make([]movie.Showtime, len(docs))
	for i, d := range docs {
		result[i] = toShowtime(d)
	}
	return result, nil
}

func toMovie(d movieDoc) movie.Movie {
	return movie.Movie{
		ID:          d.ID,
		Title:       d.Title,
		Genre:       d.Genre,
		Rating:      d.Rating,
		PosterURL:   d.PosterURL,
		Description: d.Description,
		DurationMin: d.DurationMin,
	}
}

func fromMovie(m movie.Movie) movieDoc {
	return movieDoc{
		ID:          m.ID,
		Title:       m.Title,
		Genre:       m.Genre,
		Rating:      m.Rating,
		PosterURL:   m.PosterURL,
		Description: m.Description,
		DurationMin: m.DurationMin,
	}
}

func toShowtime(d showtimeDoc) movie.Showtime {
	return movie.Showtime{
		ID:          d.ID,
		MovieID:     d.MovieID,
		Hall:        d.Hall,
		StartTime:   d.StartTime,
		EndTime:     d.EndTime,
		Rows:        d.Rows,
		SeatsPerRow: d.SeatsPerRow,
		Price:       shared.NewMoney(d.PriceCents, d.Currency),
	}
}

func fromShowtime(s movie.Showtime) showtimeDoc {
	return showtimeDoc{
		ID:          s.ID,
		MovieID:     s.MovieID,
		Hall:        s.Hall,
		StartTime:   s.StartTime,
		EndTime:     s.EndTime,
		Rows:        s.Rows,
		SeatsPerRow: s.SeatsPerRow,
		PriceCents:  s.Price.Cents(),
		Currency:    s.Price.Currency(),
	}
}
