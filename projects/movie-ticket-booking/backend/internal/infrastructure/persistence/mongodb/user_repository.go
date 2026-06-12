package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

const usersCollection = "users"

type userDoc struct {
	ID           string    `bson:"_id"`
	Email        string    `bson:"email"`
	PasswordHash string    `bson:"password_hash"`
	FirstName    string    `bson:"first_name"`
	LastName     string    `bson:"last_name"`
	Roles        []string  `bson:"roles"`
	CreatedAt    time.Time `bson:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at"`
}

// UserRepository is the MongoDB implementation of user.Repository.
type UserRepository struct {
	db *mongo.Database
}

func NewUserRepository(db *mongo.Database) *UserRepository {
	return &UserRepository{db: db}
}

// EnsureIndexes creates the unique email index. Idempotent — safe to call on every startup.
func (r *UserRepository) EnsureIndexes(ctx context.Context) error {
	_, err := r.db.Collection(usersCollection).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*user.User, error) {
	var doc userDoc
	err := r.db.Collection(usersCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, user.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return docToUser(doc), nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var doc userDoc
	err := r.db.Collection(usersCollection).FindOne(ctx, bson.M{"email": email}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, user.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return docToUser(doc), nil
}

func (r *UserRepository) Save(ctx context.Context, u *user.User) error {
	_, err := r.db.Collection(usersCollection).InsertOne(ctx, userToDoc(u))
	if mongo.IsDuplicateKeyError(err) {
		return user.ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func docToUser(d userDoc) *user.User {
	roles := make([]user.RoleType, len(d.Roles))
	for i, r := range d.Roles {
		roles[i] = user.RoleType(r)
	}
	return &user.User{
		ID:           d.ID,
		Email:        d.Email,
		PasswordHash: d.PasswordHash,
		FirstName:    d.FirstName,
		LastName:     d.LastName,
		Roles:        roles,
		CreatedAt:    d.CreatedAt,
		UpdatedAt:    d.UpdatedAt,
	}
}

func userToDoc(u *user.User) userDoc {
	roles := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = string(r)
	}
	return userDoc{
		ID:           u.ID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		Roles:        roles,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}
