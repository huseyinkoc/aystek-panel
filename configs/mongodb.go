package configs

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var DB *mongo.Client

func Init() error {
	// Ortam değişkenlerinden MongoDB URI'sini al
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("MONGO_URI ortam değişkeni ayarlanmamış")
	}

	// MongoDB istemcisi oluştur
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("MongoDB istemcisi oluşturulamadı: %v", err)
	}

	// Bağlantıyı kur
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatalf("MongoDB'ye bağlanılamadı: %v", err)
	}

	// Bağlantıyı test et
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("MongoDB'ye ping atılamadı: %v", err)
	}

	log.Println("MongoDB bağlantısı başarılı")
	DB = client

	return nil
}
