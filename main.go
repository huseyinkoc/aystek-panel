package main

import (
	"admin-panel/configs"
	_ "admin-panel/docs" // Swagger dokümantasyonu için gerekli
	"admin-panel/middlewares"
	"admin-panel/routes"
	"admin-panel/services"
	"context"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func init() {
	// .env dosyasını yükle
	err := godotenv.Load()
	if err != nil {
		log.Println(".env dosyası yüklenemedi, ortam değişkenleri kullanılacak")
	}
}

// @title           Admin Panel API
// @version         1.0
// @description     This is the API documentation for the admin panel project.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.email  support@example.com

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @BasePath  /

// @security BearerAuth
// @in header
// @name Authorization
func main() {

	// PORT env'den al
	port := os.Getenv("PORT")
	if port == "" {
		port = "9090" // varsayılan port
	}
	log.Printf("Sunucu %s portunda başlatılıyor...", port)

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

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

	emailConfig := configs.LoadEmailConfig()

	// Servisleri başlat
	services.InitEmailService(emailConfig)
	log.Println("Email service initialized")
	services.InitUserService(configs.DB)
	services.InitPostService(configs.DB)
	services.InitPageService(configs.DB)
	services.InitCategoryService(configs.DB)
	services.InitTagService(configs.DB)
	services.InitMediaService(configs.DB)
	services.InitCommentService(configs.DB)
	services.InitNotificationService(configs.DB)
	services.InitRolesService(configs.DB)
	services.InitPermissionService(configs.DB)
	services.InitMenuService(configs.DB)
	services.InitContactService(configs.DB)
	services.InitEmailVerificationService(configs.DB)
	services.InitPasswordResetService(configs.DB)
	services.InitLocalizedContentService(configs.DB)
	services.InitLanguageService(configs.DB)
	services.InitActivityLogService(configs.DB)
	services.InitSettingsService(configs.DB)
	services.InitSliderService(configs.DB)
	services.InitTokenService(configs.DB)

	log.Println("Tüm servisler başarıyla başlatıldı.")

	// Gin başlat
	r := gin.Default()

	// CORS en başta
	r.Use(middlewares.CORSMiddleware())

	// Swagger route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Dil ve SEO dostu rotalar
	r.GET("/:lang/:slug", func(c *gin.Context) {
		lang := c.Param("lang")
		slug := c.Param("slug")

		// Burada dil ve slug'a göre içeriği getirme işlemi yapılacak
		// Örneğin:
		// content := getContentByLangAndSlug(lang, slug)

		c.JSON(http.StatusOK, gin.H{
			"language": lang,
			"slug":     slug,
			// "content":  content,
		})
	})

	// Logger middleware, tüm rotalar için etkin
	r.Use(middlewares.LoggerMiddleware())

	// Global hata middleware'ini ekleyin
	r.Use(middlewares.ErrorLoggingMiddleware())

	// Rotaları yükle
	routes.AuthRoutes(r)
	routes.UserRoutes(r)
	routes.PostRoutes(r)
	routes.PageRoutes(r) // Sayfa rotalarını yükle
	routes.CategoryRoutes(r)
	routes.TagRoutes(r)
	routes.MediaRoutes(r) // Medya rotalarını ekle
	routes.RegisterCommentRoutes(r)
	routes.RegisterNotificationRoutes(r)
	routes.RoleRoutes(r)
	routes.MenuRoutes(r)
	routes.ContactRoutes(r)
	routes.LocalizedContentRoutes(r)
	routes.LanguageRoutes(r)
	routes.ActivityLogRoutes(r)
	routes.SettingsRoutes(r)
	routes.MaintenanceRoutes(r)
	routes.SliderRoutes(r)

	// GraphQL rotası
	routes.GraphQLRoutes(r)

	r.Static("/uploads", "./uploads")
	r.Static("/docs", "./docs")

	// Sunucuyu başlat
	r.Run(":" + port)
}
