package controllers

import (
	"admin-panel/helpers"
	"admin-panel/models"
	"admin-panel/services"
	"admin-panel/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// CreatePostHandler handles creating a new post
// @Summary Create a new post
// @Description Create a new post with localized content, tags, and categories
// @Tags Posts
// @Accept json
// @Produce json
// @Param post body models.Post true "Post Data"
// @Success 201 {object} models.Post
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /posts [post]
func CreatePostHandler(c *gin.Context) {

	var input struct {
		Localizations map[string]models.LocalizedField `json:"localizations" binding:"required"`
		Status        string                           `json:"status"`
		CategoryIDs   []primitive.ObjectID             `json:"category_ids"`
		TagIDs        []primitive.ObjectID             `json:"tag_ids"`
		PublishDate   *time.Time                       `json:"publish_date"`
		MetaTags      map[string]models.MetaTag        `json:"meta_tags"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Slug oluşturma
	for lang, localization := range input.Localizations {
		if localization.Slug == "" {
			localization.Slug = utils.GenerateSlug(localization.Title)
		}
		input.Localizations[lang] = localization
	}

	// Varsayılan durum
	if input.Status == "" {
		input.Status = "draft"
	}

	// Yeni Post oluşturma
	post := models.Post{
		ID:            primitive.NewObjectID(),
		Localizations: input.Localizations,
		Status:        input.Status,
		CategoryIDs:   input.CategoryIDs,
		TagIDs:        input.TagIDs,
		PublishDate:   input.PublishDate,
		MetaTags:      input.MetaTags,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Veritabanına kaydet
	if err := services.CreatePost(c.Request.Context(), &post); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create post", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Post created successfully", "post": post})
}

// @Summary Get all posts
// @Description Retrieve all posts with their details
// @Tags Posts
// @Produce json
// @Success 200 {array} models.Post
// @Router /posts [get]
func GetAllPostsHandler(c *gin.Context) {
	posts, err := services.GetAllPosts(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve posts"})
		return
	}
	c.JSON(http.StatusOK, posts)
}

// GetPostByIDHandler retrieves a post by its ID
// @Summary Get a post by ID
// @Description Retrieve a single post by its unique identifier, with localized content
// @Tags Posts
// @Produce json
// @Param id path string true "Post ID"
// @Param lang query string false "Language code for localization (e.g., 'en', 'tr')"
// @Success 200 {object} models.Post
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /posts/{id} [get]
func GetPostByIDHandler(c *gin.Context) {
	id := c.Param("id")
	lang := c.DefaultQuery("lang", "en")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
		return
	}

	post, err := services.GetPostByID(c.Request.Context(), objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch post"})
		return
	}

	localizedContent, exists := post.Localizations[lang]
	if !exists {
		localizedContent = post.Localizations["en"] // Varsayılan dil
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         post.ID.Hex(),
		"slug":       localizedContent.Slug,
		"title":      localizedContent.Title,
		"content":    localizedContent.Content,
		"status":     post.Status,
		"categories": post.CategoryIDs,
		"tags":       post.TagIDs,
		"meta_tags":  post.MetaTags[lang],
	})
}

// UpdatePostHandler updates an existing post
// @Summary Update a post
// @Description Update post details such as localized content, tags, and categories
// @Tags Posts
// @Accept json
// @Produce json
// @Param id path string true "Post ID"
// @Param post body models.Post true "Post Data"
// @Success 200 {object} models.Post
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /posts/{id} [put]
func UpdatePostHandler(c *gin.Context) {
	id := c.Param("id")
	role, exists := c.Get("role")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	hasPermission, err := helpers.HasModulePermission(c.Request.Context(), role.(string), "posts", "update")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions", "details": err.Error()})
		return
	}

	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to update posts"})
		return
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
		return
	}

	var input struct {
		Localizations map[string]models.LocalizedField `json:"localizations"`
		Status        string                           `json:"status"`
		CategoryIDs   []primitive.ObjectID             `json:"category_ids"`
		TagIDs        []primitive.ObjectID             `json:"tag_ids"`
		PublishDate   *time.Time                       `json:"publish_date"`
		MetaTags      map[string]models.MetaTag        `json:"meta_tags"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mevcut postu al
	post, err := services.GetPostByID(c.Request.Context(), objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch post", "details": err.Error()})
		return
	}

	// Alanları güncelle
	if input.Localizations != nil {
		for lang, localization := range input.Localizations {
			if localization.Slug == "" {
				localization.Slug = utils.GenerateSlug(localization.Title)
			}
			post.Localizations[lang] = localization
		}
	}
	if input.Status != "" {
		post.Status = input.Status
	}
	if input.CategoryIDs != nil {
		post.CategoryIDs = input.CategoryIDs
	}
	if input.TagIDs != nil {
		post.TagIDs = input.TagIDs
	}
	if input.PublishDate != nil {
		post.PublishDate = input.PublishDate
	}
	if input.MetaTags != nil {
		post.MetaTags = input.MetaTags
	}

	post.UpdatedAt = time.Now()

	// Veritabanında güncelle
	if err := services.UpdatePost(c.Request.Context(), post); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update post", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Post updated successfully", "post": post})
}

// GetFilteredPostsHandler retrieves posts based on filters
// @Summary Get filtered posts
// @Description Retrieve posts by category, tag, or status
// @Tags Posts
// @Produce json
// @Param category query string false "Category ID to filter posts"
// @Param tag query string false "Tag ID to filter posts"
// @Param status query string false "Status to filter posts (e.g., 'draft', 'published')"
// @Success 200 {array} models.Post
// @Failure 500 {object} map[string]string
// @Router /posts/filter [get]
func GetFilteredPostsHandler(c *gin.Context) {
	category := c.Query("category")
	tag := c.Query("tag")
	status := c.Query("status")

	filter := bson.M{}
	if category != "" {
		filter["categories"] = category
	}
	if tag != "" {
		filter["tags"] = tag
	}
	if status != "" {
		filter["status"] = status
	}

	posts, err := services.GetFilteredPosts(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve filtered posts", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, posts)
}

// GetPostsByLanguageHandler retrieves posts in a specific language
// @Summary Get posts by language
// @Description Retrieve all posts localized to a specific language
// @Tags Posts
// @Produce json
// @Param lang path string true "Language code (e.g., 'en', 'tr')"
// @Success 200 {array} models.Post
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /posts/lang/{lang} [get]
func GetPostsByLanguageHandler(c *gin.Context) {
	lang := c.Param("lang")

	posts, err := services.GetAllPosts(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve posts", "details": err.Error()})
		return
	}

	localizedPosts := []map[string]interface{}{}
	for _, post := range posts {
		if localization, ok := post.Localizations[lang]; ok {
			localizedPosts = append(localizedPosts, map[string]interface{}{
				"id":         post.ID.Hex(),
				"slug":       localization.Slug,
				"title":      localization.Title,
				"content":    localization.Content,
				"status":     post.Status,
				"categories": post.CategoryIDs,
				"tags":       post.TagIDs,
				"meta_tags":  post.MetaTags[lang],
			})
		}
	}

	if len(localizedPosts) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "No posts found for the specified language"})
		return
	}

	c.JSON(http.StatusOK, localizedPosts)
}

func GetPostByLangAndSlugHandler(c *gin.Context) {
	ctx := c.Request.Context()
	lang := c.Param("lang")
	slug := c.Param("slug")

	post, err := services.GetPostByLangAndSlug(ctx, lang, slug)
	if err != nil {
		c.JSON(404, gin.H{"error": "Post not found"})
		return
	}

	c.JSON(200, gin.H{"data": post})
}

// DeletePostHandler deletes a post by its ID
// @Summary Delete a post
// @Description Remove a post permanently by its unique identifier
// @Tags Posts
// @Param id path string true "Post ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /posts/{id} [delete]
func DeletePostHandler(c *gin.Context) {
	id := c.Param("id") // Get the post ID from the path parameter

	// Check if the ID is valid
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post ID"})
		return
	}

	// Call the service to delete the post
	err = services.DeletePost(c.Request.Context(), objectID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete post", "details": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil) // Return 204 No Content on success
}
