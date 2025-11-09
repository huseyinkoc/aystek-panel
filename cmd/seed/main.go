package main

import (
	"admin-panel/configs"
	"admin-panel/seeds"
	"admin-panel/services"
	"context"
	"log"
	"time"

	"github.com/joho/godotenv"
)

func init() {
	// .env dosyasını yükle
	err := godotenv.Load()
	if err != nil {
		log.Println(".env dosyası yüklenemedi, ortam değişkenleri kullanılacak")
	}
}

func main() {
	log.Println("🚀 Seed işlemi başlatılıyor...")

	// Veritabanı bağlantısını başlat
	if err := configs.Init(); err != nil {
		log.Fatalf("Veritabanı başlatılamadı: %v", err)
	}

	// Uygulama sonlandığında bağlantıyı kapat
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer func() {
		if err := configs.DB.Disconnect(ctx); err != nil {
			log.Fatalf("MongoDB bağlantısı kapatılamadı: %v", err)
		}
	}()

	// Servisleri başlat
	services.InitPermissionService(configs.DB)
	services.InitRolesService(configs.DB)
	services.InitUserService(configs.DB)

	// Permission seed
	permissions, err := seeds.SeedPermissions(ctx)
	if err != nil {
		log.Fatal("❌ Permission seed hatası:", err)
	}

	// Role seed
	err = seeds.SeedRoles(ctx, permissions)
	if err != nil {
		log.Fatal("❌ Role seed hatası:", err)
	}

	log.Println("✅ Tüm seed işlemleri başarıyla tamamlandı.")
}
