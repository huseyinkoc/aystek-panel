package utils

import (
	"regexp"
	"strings"
)

// GenerateSlug generates a URL-friendly slug from a given title
func GenerateSlug(title string) string {
	// Boş giriş için kontrol
	if strings.TrimSpace(title) == "" {
		return "default-slug"
	}

	// Büyük harfleri küçük harfe çevir
	slug := strings.ToLower(title)

	// Türkçe karakterleri dönüştürme
	trMap := map[string]string{
		"ç": "c", "ğ": "g", "ı": "i", "ö": "o", "ş": "s", "ü": "u",
	}
	for k, v := range trMap {
		slug = strings.ReplaceAll(slug, k, v)
	}

	// Özel karakterleri ve noktalama işaretlerini kaldır
	re := regexp.MustCompile(`[^a-z0-9\s-]`)
	slug = re.ReplaceAllString(slug, "")

	// Boşlukları tire (-) ile değiştir
	slug = strings.ReplaceAll(slug, " ", "-")

	// Birden fazla tireyi tek bir tireye indir
	re = regexp.MustCompile(`-+`)
	slug = re.ReplaceAllString(slug, "-")

	// Baştaki ve sondaki tireleri kaldır
	slug = strings.Trim(slug, "-")

	return slug
}
