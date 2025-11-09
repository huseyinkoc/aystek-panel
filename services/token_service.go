package services

import (
	"admin-panel/configs"
	"admin-panel/models"
	"context"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	accessTokenCollection  *mongo.Collection
	refreshTokenCollection *mongo.Collection
)

// Main.go’dan: services.InitTokenService(configs.DB) çağrılmalı
func InitTokenService(client *mongo.Client) {
	dbName := os.Getenv("MONGO_DBNAME")
	if dbName == "" {
		dbName = "admin_panel"
	}
	db := client.Database(dbName) // istersen .env ile dinamikleştir
	accessTokenCollection = db.Collection("access_tokens")
	refreshTokenCollection = db.Collection("refresh_tokens")
}

// ---------- ACCESS TOKEN ----------

func SaveAccessToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	doc := models.AccessToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	_, err := accessTokenCollection.InsertOne(ctx, doc)
	return err
}

func GetValidAccessToken(ctx context.Context, userID string) (string, time.Time, error) {
	filter := bson.M{
		"user_id":    userID,
		"expires_at": bson.M{"$gt": time.Now()},
	}
	var doc models.AccessToken
	err := accessTokenCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		return "", time.Time{}, err
	}
	return doc.Token, doc.ExpiresAt, nil
}

func DeleteAccessTokens(ctx context.Context, userID string) error {
	_, err := accessTokenCollection.DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}

// ---------- REFRESH TOKEN ----------

func SaveRefreshToken(ctx context.Context, userID, token string) error {
	doc := models.RefreshToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(configs.GetRefreshExpiry()),
		CreatedAt: time.Now(),
	}
	_, err := refreshTokenCollection.InsertOne(ctx, doc)
	return err
}

func GetValidRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	filter := bson.M{
		"user_id":    userID,
		"expires_at": bson.M{"$gt": time.Now()},
	}
	var doc models.RefreshToken
	err := refreshTokenCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		return "", time.Time{}, err
	}
	return doc.Token, doc.ExpiresAt, nil
}

func ValidateRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	var doc models.RefreshToken
	err := refreshTokenCollection.FindOne(ctx, bson.M{
		"token":      refreshToken,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&doc)
	if err != nil {
		return "", err
	}
	return doc.UserID, nil
}

func DeleteRefreshTokens(ctx context.Context, userID string) error {
	_, err := refreshTokenCollection.DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}
