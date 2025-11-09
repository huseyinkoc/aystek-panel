package seeds

import (
	"admin-panel/models"
	"admin-panel/services"
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func SeedPermissions(ctx context.Context) ([]models.Permission, error) {
	log.Println("🚀 Permission seed başlatılıyor...")

	permissions := []models.Permission{
		{
			ID:        primitive.NewObjectID(),
			Module:    "users",
			Actions:   []string{"create", "read", "update", "delete"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "system",
			UpdatedBy: "system",
		},
		{
			ID:        primitive.NewObjectID(),
			Module:    "posts",
			Actions:   []string{"create", "read", "update", "delete"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "system",
			UpdatedBy: "system",
		},
		{
			ID:        primitive.NewObjectID(),
			Module:    "settings",
			Actions:   []string{"read", "update"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "system",
			UpdatedBy: "system",
		},
	}

	for _, p := range permissions {
		_, err := services.CreatePermission(ctx, p)
		if err != nil {
			log.Printf("⚠️ Permission eklenemedi: %s (%v)\n", p.Module, err)
		}
	}

	log.Println("✅ Permission seed tamamlandı.")
	return permissions, nil
}
