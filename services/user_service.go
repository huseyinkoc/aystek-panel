package services

import (
	"admin-panel/models"
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Global koleksiyon referansları
var (
	userCollection *mongo.Collection
	roleCollection *mongo.Collection
)

// InitUserService initializes the user, role, and language collections
// InitUserService initializes the user and role collections
func InitUserService(client *mongo.Client) {
	db := client.Database("admin_panel")
	userCollection = db.Collection("users")
	roleCollection = db.Collection("roles")
}

// CreateUser inserts a new user into the database
func CreateUser(user models.User) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	return userCollection.InsertOne(ctx, user)
}

// GetAllUsers retrieves all users from the database
func GetAllUsers() ([]models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := userCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}

// UpdateUser updates a user in the database
func UpdateUser(id primitive.ObjectID, update bson.M) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"_id": id}
	return userCollection.UpdateOne(ctx, filter, bson.M{"$set": update})
}

// DeleteUser deletes a user by ID
func DeleteUser(id primitive.ObjectID) (*mongo.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"_id": id}
	return userCollection.DeleteOne(ctx, filter)
}

// HashPassword hashes a plain text password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a hashed password with a plain text password
func CheckPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GetUserByUsername retrieves a user by username
func GetUserByUsername(username string) (models.User, error) {
	var user models.User

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return user, errors.New("user not found")
		}
		return user, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(email string) (models.User, error) {
	var user models.User

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return user, errors.New("user not found")
		}
		return user, err
	}

	return user, nil
}

// GetUserByPhoneNumber retrieves a user by phone number
func GetUserByPhoneNumber(phoneNumber string) (models.User, error) {
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := userCollection.FindOne(ctx, bson.M{"phone_number": phoneNumber}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return user, errors.New("user not found")
		}
		return user, err
	}
	return user, nil
}

// VerifyUserAccount sets the is_verified field to true for a specific user
func VerifyUserAccount(ctx context.Context, userID primitive.ObjectID) error {
	filter := bson.M{"_id": userID}
	update := bson.M{"$set": bson.M{"is_verified": true}}

	result, err := userCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// GetUserEmailByID retrieves the email address of a user by their ID
func GetUserEmailByID(ctx context.Context, userID primitive.ObjectID) (string, error) {
	var user struct {
		Email string `bson:"email"`
	}

	err := userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", errors.New("user not found")
		}
		return "", err
	}

	return user.Email, nil
}

// UpdateUserPassword updates the password of a user by their ID
func UpdateUserPassword(ctx context.Context, userID primitive.ObjectID, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to hash password")
	}

	filter := bson.M{"_id": userID}
	update := bson.M{"$set": bson.M{"password": string(hashedPassword)}}

	result, err := userCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// GetUserIDByEmail retrieves the user ID for a given email address
func GetUserIDByEmail(ctx context.Context, email string) (primitive.ObjectID, error) {
	var user struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return primitive.NilObjectID, errors.New("user not found")
		}
		return primitive.NilObjectID, err
	}

	return user.ID, nil
}

// UpdateUserPreferredLanguage updates user's preferred language
func UpdateUserPreferredLanguage(userID string, languageCode string) error {
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	_, err = userCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		bson.M{"$set": bson.M{
			"preferred_language": languageCode,
			"updated_at":         time.Now(),
		}},
	)
	return err
}

// IsLanguageEnabled checks if a given language code is active
func IsLanguageEnabled(languageCode string) (bool, error) {
	var lang models.Language
	err := languageCollection.FindOne(context.Background(), bson.M{"code": languageCode, "enabled": true}).Decode(&lang)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetUserByID retrieves a user by ID
func GetUserByID(ctx context.Context, id string) (*models.User, error) {
	// String ID’yi ObjectID’ye dönüştür
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %v", err)
	}

	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func GetUserByObjectID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ApproveUserByAdmin sets a user's approval flag to true (only if email is verified)
func ApproveUserByAdmin(ctx context.Context, id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"is_approved_by_admin": true,
			"updated_at":           time.Now(),
		},
	}

	filter := bson.M{
		"_id":               id,
		"is_email_verified": true,
	}

	result, err := userCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to approve user: %v", err)
	}

	if result.MatchedCount == 0 {
		return errors.New("no matching verified user found for approval")
	}

	return nil
}

// UpdateUserRoles updates the roles of a user by ID
func UpdateUserRoles(userID primitive.ObjectID, roles []primitive.ObjectID) error {
	update := bson.M{
		"$set": bson.M{
			"roles":      roles,
			"updated_at": time.Now(),
		},
	}
	_, err := userCollection.UpdateOne(context.TODO(), bson.M{"_id": userID}, update)
	return err
}

// GetUserRoles retrieves all role documents for a given user-
func GetUserRoles(userID primitive.ObjectID) ([]models.Role, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	if err := userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		return nil, err
	}

	if len(user.Roles) == 0 {
		return []models.Role{}, nil
	}

	cursor, err := roleCollection.Find(ctx, bson.M{"_id": bson.M{"$in": user.Roles}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []models.Role
	for cursor.Next(ctx) {
		var role models.Role
		if err := cursor.Decode(&role); err == nil {
			roles = append(roles, role)
		}
	}
	return roles, nil
}
