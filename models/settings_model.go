package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ApplicationSettings struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Title       map[string]string  `bson:"title" json:"title"`             // Çok dilli başlık
	Description map[string]string  `bson:"description" json:"description"` // Çok dilli açıklama
	//SocialMedia     map[string]string  `bson:"social_media" json:"social_media"` // Sosyal medya bağlantıları
	SocialMedia     map[string]SocialMedia `bson:"social_media" json:"social_media"` // Sosyal medya bağlantıları
	ContactInfo     map[string]string      `bson:"contact_info" json:"contact_info"` // İletişim bilgileri (telefon, e-posta vb.)
	MaintenanceMode bool                   `bson:"maintenance_mode" json:"maintenance_mode"`
	MaintenanceMsg  map[string]string      `bson:"maintenance_msg" json:"maintenance_msg"` // Çok dilli bakım modu mesajı
	MetaTags        map[string]MetaTag     `bson:"meta_tags" json:"meta_tags"`             // SEO meta bilgileri
	SupportedLangs  []string               `bson:"supported_langs" json:"supported_langs"` // Desteklenen diller
	DefaultLang     string                 `bson:"default_lang" json:"default_lang"`       // Varsayılan dil
	AnalyticsCode   string                 `bson:"analytics_code" json:"analytics_code"`   // Google Analytics kodu
	LogoURL         string                 `bson:"logo_url" json:"logo_url"`               // Logo URL'si
	FaviconURL      string                 `bson:"favicon_url" json:"favicon_url"`         // Favicon URL'si
	UpdatedAt       time.Time              `bson:"updated_at" json:"updated_at"`
	UpdatedBy       string                 `bson:"updated_by" json:"updated_by"`
}

type SocialMedia struct {
	Name   string `bson:"name" json:"name"  example:"Facebook"`              // Örnek: Facebook, Twitter
	URL    string `bson:"url" json:"url example:"https://www.facebook.com""` // Örnek: https://facebook.com/yourpage
	Active bool   `bson:"active" json:"active" example:true`                 // Aktif mi?
}

type MaintenanceToggleMode struct {
	Enable  bool              `json:"enable" example:true`
	Message map[string]string `json:"message" example:{"message": "Maintenance mode enabled"}`
}
