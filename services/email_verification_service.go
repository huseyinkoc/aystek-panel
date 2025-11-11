package services

import (
	"admin-panel/models"
	"admin-panel/templates"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var emailVerificationCollection *mongo.Collection // MongoDB collection

func InitEmailVerificationService(client *mongo.Client) {
	emailVerificationCollection = client.Database("admin_panel").Collection("email_verifications")
}

func GenerateEmailVerificationToken(userID primitive.ObjectID) (string, error) {
	// Rastgele bir token oluştur
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Token veritabanına kaydet
	verificationToken := models.EmailVerificationToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	_, err := emailVerificationCollection.InsertOne(context.Background(), verificationToken)
	if err != nil {
		return "", err
	}

	return token, nil
}

// VerifyEmailToken verifies the email token and activates the user's account
func VerifyEmailToken(ctx context.Context, token string) error {
	var verificationToken models.EmailVerificationToken
	err := emailVerificationCollection.FindOne(ctx, bson.M{"token": token}).Decode(&verificationToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return errors.New("invalid or expired token")
		}
		return err
	}

	// Check if the token has expired
	if time.Now().After(verificationToken.ExpiresAt) {
		return errors.New("token expired")
	}

	// Call the user service to verify the account
	err = VerifyUserAccount(ctx, verificationToken.UserID)
	if err != nil {
		return err
	}

	// Delete the used token
	_, err = emailVerificationCollection.DeleteOne(ctx, bson.M{"_id": verificationToken.ID})
	if err != nil {
		return err
	}

	return nil
}

func SendVerificationEmail(ctx context.Context, userID primitive.ObjectID, token string) error {
	// Kullanıcı bilgilerini al (email + username)
	user, err := GetUserByObjectID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve user: %w", err)
	}

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	// Doğrulama bağlantısını oluştur
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", frontendURL, token)

	subject := "AYSTEK - E-posta Doğrulama"
	// Şablonu templates modülünden al
	body := templates.VerificationEmailTemplate(user.Username, verificationURL)

	// E-posta gönder
	if err := SendEmail([]string{user.Email}, subject, body); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}
	return nil
}
