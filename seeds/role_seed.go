package seeds

import (
	"admin-panel/models"
	"admin-panel/services"
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func SeedRoles(ctx context.Context, permissions []models.Permission) error {
	log.Println("🚀 Role seed başlatılıyor...")

	// 1️⃣ Admin kullanıcı ID'sini bul
	adminUser, err := services.GetUserByEmail("bmhuseyinkoc@gmail.com")
	if err != nil {
		log.Printf("⚠️ Admin kullanıcı bulunamadı, dummy ID kullanılacak: %v\n", err)
		adminUser.ID = primitive.NewObjectID()
	}

	var adminPerms []primitive.ObjectID
	var editorPerms []primitive.ObjectID

	// 2️⃣ İzinleri rollerle eşleştir
	for _, perm := range permissions {
		adminPerms = append(adminPerms, perm.ID)
		if perm.Module == "posts" {
			editorPerms = append(editorPerms, perm.ID)
		}
	}

	// 3️⃣ Roller oluşturuluyor
	roles := []models.Role{
		{
			ID:          primitive.NewObjectID(),
			Name:        "admin",
			Description: "Full system access",
			Permissions: adminPerms,
			IsSystem:    true,
			CreatedBy:   adminUser.ID,
			UpdatedBy:   adminUser.ID,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          primitive.NewObjectID(),
			Name:        "editor",
			Description: "Can manage posts only",
			Permissions: editorPerms,
			IsSystem:    false,
			CreatedBy:   adminUser.ID,
			UpdatedBy:   adminUser.ID,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	// 4️⃣ Roller veritabanına ekleniyor
	for _, role := range roles {
		_, err := services.CreateRole(ctx, role)
		if err != nil {
			log.Printf("⚠️ Rol eklenemedi: %s (%v)\n", role.Name, err)
		}
	}

	log.Println("✅ Role seed tamamlandı.")
	return nil
}
