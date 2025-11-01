package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UploadMediaHandler uploads a new media file
// @Summary Upload a new media file
// @Description Upload a file to the media library
// @Tags Media
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Media file to upload"
// @Success 201 {object} models.Media "File uploaded successfully"
// @Failure 400 {object} map[string]interface{} "No file uploaded or invalid request"
// @Failure 500 {object} map[string]interface{} "Failed to save file or record"
// @Router /media/upload [post]
func UploadMediaHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file is uploaded"})
		return
	}

	// Dosyayı uploads klasörüne kaydet
	uploadPath := "uploads"
	if _, err := os.Stat(uploadPath); os.IsNotExist(err) {
		os.Mkdir(uploadPath, os.ModePerm)
	}

	filePath := filepath.Join(uploadPath, file.Filename)
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Yükleyen kullanıcıyı alın
	uploadedBy, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Medya kaydı ekle
	media := models.Media{
		FileName:   file.Filename,
		FilePath:   filePath,
		FileType:   filepath.Ext(file.Filename),
		FileSize:   file.Size,
		UploadedBy: uploadedBy.(string),
	}
	_, err = services.SaveMediaRecord(media)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save media record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "file_path": filePath})
}

// GetAllMediaHandler retrieves all media files
// @Summary Get all media files
// @Description Retrieve all media files in the library
// @Tags Media
// @Produce json
// @Success 200 {array} models.Media "List of media files"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve media files"
// @Router /media [get]
func GetAllMediaHandler(c *gin.Context) {
	media, err := services.GetAllMedia()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve media files"})
		return
	}

	c.JSON(http.StatusOK, media)
}

// DeleteMediaHandler deletes a media file
// @Summary Delete media file
// @Description Remove a specific media file by its ID
// @Tags Media
// @Param id path string true "Media file ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid media ID"
// @Failure 404 {object} map[string]interface{} "Media file not found"
// @Failure 500 {object} map[string]interface{} "Failed to delete media file"
// @Router /media/{id} [delete]
func DeleteMediaHandler(c *gin.Context) {
	idParam := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid media ID"})
		return
	}

	// Veritabanından medya kaydını sil
	result, err := services.DeleteMedia(id)
	if err != nil || result.DeletedCount == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete media"})
		return
	}

	// Opsiyonel: Dosya sisteminden de sil
	filePath := "uploads/" + idParam // Örnek dosya yolu, MongoDB'den dosya yolunu da çekebilirsiniz.
	if err := os.Remove(filePath); err != nil {
		fmt.Println("Warning: File not found or failed to delete:", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Media deleted successfully"})
}

// GetMediaDetailHandler retrieves details of a media file
// @Summary Get media details
// @Description Retrieve details of a specific media file by its ID
// @Tags Media
// @Produce json
// @Param id path string true "Media file ID"
// @Success 200 {object} models.Media "Media file details"
// @Failure 400 {object} map[string]interface{} "Invalid media ID"
// @Failure 404 {object} map[string]interface{} "Media file not found"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve media details"
// @Router /media/{id} [get]
func GetMediaDetailHandler(c *gin.Context) {
	idParam := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid media ID"})
		return
	}

	media, err := services.GetMediaByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Media not found"})
		return
	}

	c.JSON(http.StatusOK, media)
}

// GetFilteredMediaHandler retrieves media files based on filters
// @Summary Filter media files
// @Description Retrieve media files filtered by file name, type, or upload date
// @Tags Media
// @Produce json
// @Param file_name query string false "Filter by file name"
// @Param file_type query string false "Filter by file type"
// @Param start_date query string false "Start date for upload filter (YYYY-MM-DD)"
// @Param end_date query string false "End date for upload filter (YYYY-MM-DD)"
// @Success 200 {array} models.Media "Filtered list of media files"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve filtered media files"
// @Router /media/filter [get]
func GetFilteredMediaHandler(c *gin.Context) {
	// Sorgu parametrelerini al
	fileName := c.Query("file_name")
	fileType := c.Query("file_type")
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	// Filtreleme kriterlerini oluştur
	filter := bson.M{}
	if fileName != "" {
		filter["file_name"] = bson.M{"$regex": fileName, "$options": "i"} // Case-insensitive arama
	}
	if fileType != "" {
		filter["file_type"] = fileType
	}
	if startDate != "" && endDate != "" {
		start, err1 := time.Parse("2006-01-02", startDate)
		end, err2 := time.Parse("2006-01-02", endDate)
		if err1 == nil && err2 == nil {
			filter["uploaded_at"] = bson.M{
				"$gte": start.Unix(),
				"$lte": end.Unix(),
			}
		}
	}

	// Medya dosyalarını getir
	media, err := services.GetFilteredMedia(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve media files"})
		return
	}

	c.JSON(http.StatusOK, media)
}
