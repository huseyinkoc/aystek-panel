package controllers

import (
	"admin-panel/configs"
	"admin-panel/middlewares"
	"admin-panel/models"
	"admin-panel/services"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// Claims yapısı - JWT v5
type Claims struct {
	UserID            string   `json:"userID"`
	Username          string   `json:"username"`
	Email             string   `json:"email"`
	PreferredLanguage string   `json:"preferred_language"`
	Roles             []string `json:"roles"`
	jwt.RegisteredClaims
}

// Rastgele token oluştur
func generateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ------------------------------------------------------
// @Summary Kullanıcı Adı ile Giriş
// @Description Kullanıcı adı ve şifre ile giriş. Geçerli access token varsa aynı token döner; yoksa yeni access+refresh üretilir.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body object{username=string,password=string} true "Kullanıcı giriş bilgileri"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /svc/auth/login-by-username [post]
func LoginByUsernameHandler(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz giriş verisi: " + err.Error()})
		return
	}

	user, err := services.GetUserByUsername(input.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	if err := services.CheckPassword(user.Password, input.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Hatalı şifre"})
		return
	}

	// Geçerli access token varsa aynısını döndür
	if tokenStr, _, err := services.GetValidAccessToken(c.Request.Context(), user.ID.Hex()); err == nil && tokenStr != "" {
		csrf := middlewares.GetStoredCSRFToken(user.Username)
		if csrf == "" {
			csrf, _ = middlewares.GenerateCSRFToken()
			middlewares.StoreCSRFToken(user.Username, csrf)
		}
		c.JSON(http.StatusOK, gin.H{
			"token":      tokenStr,
			"csrf_token": csrf,
			"message":    "Zaten giriş yapılmış.",
			"user": gin.H{
				"id":       user.ID.Hex(),
				"username": user.Username,
				"name":     user.Name,
				"surname":  user.Surname,
				"roles":    user.Roles,
			},
		})
		return
	}

	// Yeni access + refresh oluştur
	accessExp := time.Now().Add(configs.GetJWTExpiry())
	claims := &Claims{
		UserID:            user.ID.Hex(),
		Username:          user.Username,
		Email:             user.Email,
		Roles:             user.Roles,
		PreferredLanguage: user.PreferredLanguage,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			Issuer:    "kwbsite",
		},
	}
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := accessJWT.SignedString(configs.GetJWTSecret())
	if err != nil {
		log.Println("JWT oluşturulamadı:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token oluşturulamadı"})
		return
	}
	_ = services.SaveAccessToken(c.Request.Context(), user.ID.Hex(), accessToken, accessExp)

	refreshToken := primitive.NewObjectID().Hex()
	_ = services.SaveRefreshToken(c.Request.Context(), user.ID.Hex(), refreshToken)

	csrfToken, _ := middlewares.GenerateCSRFToken()
	middlewares.StoreCSRFToken(user.Username, csrfToken)

	c.JSON(http.StatusOK, gin.H{
		"token":         accessToken,
		"csrf_token":    csrfToken,
		"refresh_token": refreshToken,
		"message":       "Giriş başarılı",
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"name":     user.Name,
			"surname":  user.Surname,
			"roles":    user.Roles,
		},
	})
}

// ------------------------------------------------------
// @Summary E-posta ile Giriş
// @Description E-posta ve şifre ile giriş. Geçerli access token varsa aynı token döner; yoksa yeni access+refresh üretilir.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body object{email=string,password=string} true "Kullanıcı giriş bilgileri"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /svc/auth/login-by-email [post]
func LoginByEmailHandler(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz giriş verisi: " + err.Error()})
		return
	}

	user, err := services.GetUserByEmail(input.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "E-posta veya şifre yanlış"})
		return
	}

	// Aktiflik kontrolleri
	if !user.IsEmailVerified {
		c.JSON(http.StatusForbidden, gin.H{"error": "Lütfen e-posta adresinizi doğrulayın"})
		return
	}
	if !user.IsApprovedByAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Hesabınız henüz yönetici tarafından onaylanmamış. Lütfen bekleyin."})
		return
	}

	if err := services.CheckPassword(user.Password, input.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "E-posta veya şifre yanlış"})
		return
	}

	// Geçerli access token varsa aynısını döndür
	if tokenStr, _, err := services.GetValidAccessToken(c.Request.Context(), user.ID.Hex()); err == nil && tokenStr != "" {
		csrf := middlewares.GetStoredCSRFToken(user.Email)
		if csrf == "" {
			csrf, _ = middlewares.GenerateCSRFToken()
			middlewares.StoreCSRFToken(user.Email, csrf)
		}
		c.JSON(http.StatusOK, gin.H{
			"token":      tokenStr,
			"csrf_token": csrf,
			"message":    "Zaten giriş yapılmış.",
			"user": gin.H{
				"id":       user.ID.Hex(),
				"username": user.Username,
				"name":     user.Name,
				"surname":  user.Surname,
				"roles":    user.Roles,
			},
		})
		return
	}

	// Yeni access + refresh oluştur
	accessExp := time.Now().Add(configs.GetJWTExpiry())
	claims := &Claims{
		UserID:            user.ID.Hex(),
		Username:          user.Username,
		Email:             user.Email,
		Roles:             user.Roles,
		PreferredLanguage: user.PreferredLanguage,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			Issuer:    "kwbsite",
		},
	}
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, _ := accessJWT.SignedString(configs.GetJWTSecret())
	_ = services.SaveAccessToken(c.Request.Context(), user.ID.Hex(), accessToken, accessExp)

	refreshToken := primitive.NewObjectID().Hex()
	_ = services.SaveRefreshToken(c.Request.Context(), user.ID.Hex(), refreshToken)

	csrfToken, _ := middlewares.GenerateCSRFToken()
	middlewares.StoreCSRFToken(user.Email, csrfToken)

	c.JSON(http.StatusOK, gin.H{
		"token":         accessToken,
		"csrf_token":    csrfToken,
		"refresh_token": refreshToken,
		"message":       "Giriş başarılı",
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"name":     user.Name,
			"surname":  user.Surname,
			"roles":    user.Roles,
		},
	})
}

// ------------------------------------------------------
// @Summary Telefon ile Giriş
// @Description Telefon + şifre ile giriş. Geçerli access token varsa aynı token döner; yoksa yeni access+refresh üretilir.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body object{phone_number=string,password=string} true "Kullanıcı giriş bilgileri"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /svc/auth/login-by-phone [post]
func LoginByPhoneHandler(c *gin.Context) {
	var input struct {
		PhoneNumber string `json:"phone_number" binding:"required"`
		Password    string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := services.GetUserByPhoneNumber(input.PhoneNumber)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}
	if err := services.CheckPassword(user.Password, input.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Hatalı şifre"})
		return
	}

	if tokenStr, _, err := services.GetValidAccessToken(c.Request.Context(), user.ID.Hex()); err == nil && tokenStr != "" {
		c.JSON(http.StatusOK, gin.H{
			"token":   tokenStr,
			"message": "Zaten giriş yapılmış.",
		})
		return
	}

	accessExp := time.Now().Add(configs.GetJWTExpiry())
	claims := &Claims{
		UserID:   user.ID.Hex(),
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			Issuer:    "kwbsite",
		},
	}
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, _ := accessJWT.SignedString(configs.GetJWTSecret())
	_ = services.SaveAccessToken(c.Request.Context(), user.ID.Hex(), accessToken, accessExp)

	refreshToken := primitive.NewObjectID().Hex()
	_ = services.SaveRefreshToken(c.Request.Context(), user.ID.Hex(), refreshToken)

	c.JSON(http.StatusOK, gin.H{
		"token":         accessToken,
		"refresh_token": refreshToken,
		"message":       "Giriş başarılı",
	})
}

// ------------------------------------------------------
// @Summary Token Doğrulama
// @Description JWT token geçerli mi kontrol eder, kullanıcı bilgisini döner.
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /svc/auth/validate [get]
func ValidateTokenHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token bulunamadı"})
		return
	}
	// Bearer prefix temizle
	if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
		tokenString = strings.TrimSpace(tokenString[7:])
	}

	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return configs.GetJWTSecret(), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token geçersiz: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token geçerli",
		"user":    claims,
	})
}

// ------------------------------------------------------
// @Summary Refresh Access Token
// @Description Geçerli refresh token ile yeni access token üretir
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body object{refresh_token=string} true "Refresh token"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /svc/auth/refresh [post]
func RefreshTokenHandler(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Eksik refresh token"})
		return
	}

	userID, err := services.ValidateRefreshToken(c.Request.Context(), input.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token geçersiz veya süresi dolmuş"})
		return
	}

	accessExp := time.Now().Add(configs.GetJWTExpiry())
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			Issuer:    "kwbsite",
		},
	}
	accessJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newAccess, _ := accessJWT.SignedString(configs.GetJWTSecret())

	// Opsiyonel: eski refresh'leri temizleyip yenisini yaz
	_ = services.DeleteRefreshTokens(c.Request.Context(), userID)
	_ = services.SaveRefreshToken(c.Request.Context(), userID, primitive.NewObjectID().Hex())

	c.JSON(http.StatusOK, gin.H{
		"token":      newAccess,
		"expires_in": accessExp.Unix(),
	})
}

// ------------------------------------------------------
// @Summary Logout
// @Description Kullanıcının tüm refresh + access + CSRF tokenlarını siler (tam çıkış).
// @Tags Auth
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /svc/auth/logout [post]
func LogoutHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		tokenString, _ = c.Cookie("access_token")
	}
	if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
		tokenString = strings.TrimSpace(tokenString[7:])
	}

	if tokenString == "" {
		c.JSON(http.StatusOK, gin.H{"message": "Token bulunamadı, yine de çıkış yapıldı"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return configs.GetJWTSecret(), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusOK, gin.H{"message": "Token geçersiz, yine de çıkış yapıldı"})
		return
	}

	userID := claims.UserID
	username := claims.Username
	email := claims.Email

	_ = services.DeleteRefreshTokens(c.Request.Context(), userID)
	_ = services.DeleteAccessTokens(c.Request.Context(), userID)

	if username != "" {
		middlewares.DeleteCSRFToken(username)
	}
	if email != "" {
		middlewares.DeleteCSRFToken(email)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Çıkış başarılı, tüm tokenlar temizlendi"})
}

// ------------------------------------------------------
// @Summary Send verification email
// @Description Belirli kullanıcıya doğrulama e-postası gönderir
// @Tags Auth
// @Param userID path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /svc/auth/send-verification/{userID} [post]
func SendVerificationEmailHandler(c *gin.Context) {
	userID := c.Param("userID")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	token, err := services.GenerateEmailVerificationToken(objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate verification token"})
		return
	}

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", frontendURL, token)
	log.Printf("🔗 Doğrulama linki: %s", verificationLink)

	_, err = services.GetUserByID(c.Request.Context(), objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	if err := services.SendVerificationEmail(c.Request.Context(), objectID, verificationLink); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// ------------------------------------------------------
// @Summary Verify email
// @Description Verifies a user's email using a token
// @Tags Auth
// @Param token path string true "Verification token"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /svc/auth/verify-email/{token} [post]
func VerifyEmailHandler(c *gin.Context) {
	raw := c.Param("token")
	if raw == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token gerekli"})
		return
	}

	// Eğer path parametreye yanlışlıkla tam URL gelirse, gerçek token'ı ayıkla
	token := raw
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			if t := u.Query().Get("token"); t != "" {
				token = t
			}
		}
	}
	// Bazı proxy’ler başa “/” ekleyebilir
	token = strings.TrimPrefix(token, "/")

	log.Printf("🔍 Email doğrulama token'ı: %s", token)

	if err := services.VerifyEmailToken(c.Request.Context(), token); err != nil {
		log.Printf("❌ Email doğrulama hatası: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token geçersiz veya süresi dolmuş"})
		return
	}

	log.Printf("✅ Email başarıyla doğrulandı")
	c.JSON(http.StatusOK, gin.H{"message": "E-posta başarıyla doğrulandı. Yönetici onayından sonra giriş yapabileceksiniz."})
}

// ------------------------------------------------------
// @Summary Request password reset
// @Description Aktif kullanıcı için şifre sıfırlama e-postası gönderir
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.RequestPasswordReset true "Email"
// @Success 200 {object} map[string]string
// @Router /svc/auth/request-password-reset [post]
func RequestPasswordResetHandler(c *gin.Context) {
	var req models.RequestPasswordReset
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ JSON parse hatası: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz istek"})
		return
	}
	// Güvenlik: Email'in var olup olmadığını söyleme
	log.Printf("📧 Şifre sıfırlama isteği: %s", req.Email)

	ctx := c.Request.Context()
	user, err := services.GetUserByEmail(req.Email)
	if err != nil {
		// Güvenlik: Email'in varlığını belli etme
		c.JSON(http.StatusOK, gin.H{"message": "Eğer e-posta kayıtlıysa, şifre sıfırlama bağlantısı gönderildi"})
		return
	}

	// Sadece aktif kullanıcı (email doğrulanmış + admin onaylı) için gönder
	if !user.IsEmailVerified || !user.IsApprovedByAdmin {
		c.JSON(http.StatusOK, gin.H{"message": "Eğer e-posta kayıtlıysa, şifre sıfırlama bağlantısı gönderildi"})
		return
	}

	token, err := generateResetToken()
	if err != nil {
		log.Printf("❌ Token oluşturma hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token oluşturulamadı"})
		return
	}

	expiresAt := time.Now().Add(30 * time.Minute)
	if err := services.CreatePasswordResetToken(ctx, req.Email, token, expiresAt); err != nil {
		log.Printf("❌ Token kaydetme hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token kaydedilemedi"})
		return
	}

	log.Printf("✅ Token oluşturuldu: %s (expires: %s)", token, expiresAt.Format(time.RFC3339))
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", frontendURL, token)
	log.Printf("🔗 Reset linki: %s", resetLink)

	if err := services.SendPasswordResetEmail(user.Email, user.Username, resetLink); err != nil {
		log.Printf("❌ E-posta gönderme hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "E-posta gönderilemedi"})
		return
	}

	log.Printf("✅ Şifre sıfırlama e-postası gönderildi: %s", req.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Şifre sıfırlama bağlantısı e-posta adresinize gönderildi"})
}

// ------------------------------------------------------
// @Summary Reset password
// @Description Token ile şifreyi sıfırlama
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.ResetPasswordTokenRequest true "Token and new password"
// @Success 200 {object} map[string]string
// @Router /svc/auth/reset-password [post] @Description Reset password with token
func ResetPasswordHandler(c *gin.Context) {
	var req models.ResetPasswordTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ JSON parse hatası: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz istek"})
		return
	}

	log.Printf("🔍 Token doğrulanıyor: %s", req.Token)
	ctx := c.Request.Context()
	email, err := services.ValidatePasswordResetToken(ctx, req.Token)
	if err != nil {
		log.Printf("❌ Token doğrulama hatası: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token geçersiz veya süresi dolmuş"})
		return
	}

	log.Printf("✅ Token geçerli, kullanıcı: %s", email)

	user, err := services.GetUserByEmail(email)
	if err != nil {
		log.Printf("❌ Kullanıcı bulunamadı: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("❌ Şifre hashleme hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Şifre güncellenemedi"})
		return
	}

	update := bson.M{
		"password": string(hashedPassword),
	}
	if _, err := services.UpdateUser(user.ID, update); err != nil {
		log.Printf("❌ Kullanıcı güncelleme hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Şifre güncellenemedi"})
		return
	}
	log.Printf("✅ Şifre hash'lendi")

	if err := services.MarkPasswordResetTokenAsUsed(ctx, req.Token); err != nil {
		log.Printf("⚠️ Token işaretleme hatası: %v", err)
	}

	log.Printf("✅ Şifre başarıyla güncellendi: %s", email)
	c.JSON(http.StatusOK, gin.H{"message": "Şifre başarıyla güncellendi"})
}

// ------------------------------------------------------
// @Summary Register new user
// @Description Yeni kullanıcı kaydı ve doğrulama e-postası gönderimi
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.RegisterRequest true "Registration data"
// @Success 201 {object} map[string]string
// @Router /svc/auth/register [post]
func RegisterHandler(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ JSON parse hatası: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz istek: " + err.Error()})
		return
	}
	log.Printf("📝 Yeni kayıt isteği: %s (%s) - Tel: %s", req.Username, req.Email, req.PhoneNumber)

	// Benzersizlik kontrolleri
	if existingUser, _ := services.GetUserByEmail(req.Email); existingUser.ID != primitive.NilObjectID {
		c.JSON(http.StatusConflict, gin.H{"error": "Bu e-posta adresi zaten kullanılıyor"})
		return
	}
	if existingUser, _ := services.GetUserByUsername(req.Username); existingUser.ID != primitive.NilObjectID {
		c.JSON(http.StatusConflict, gin.H{"error": "Bu kullanıcı adı zaten kullanılıyor"})
		return
	}
	if req.PhoneNumber != "" {
		if existingUser, _ := services.GetUserByPhoneNumber(req.PhoneNumber); existingUser.ID != primitive.NilObjectID {
			c.JSON(http.StatusConflict, gin.H{"error": "Bu telefon numarası zaten kullanılıyor"})
			return
		}
	}

	// Şifre hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("❌ Şifre hashleme hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kayıt işlemi başarısız"})
		return
	}

	// Kullanıcı oluştur
	newUser := models.User{
		Username:          req.Username,
		Email:             req.Email,
		Password:          string(hashedPassword),
		Name:              req.FirstName,
		Surname:           req.LastName,
		FullName:          fmt.Sprintf("%s %s", req.FirstName, req.LastName),
		PhoneNumber:       req.PhoneNumber,
		Roles:             []string{},
		IsEmailVerified:   false,
		IsApprovedByAdmin: false,
		PreferredLanguage: "tr",
	}

	result, err := services.CreateUser(newUser)
	if err != nil {
		log.Printf("❌ Kullanıcı kaydetme hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kayıt işlemi başarısız"})
		return
	}
	userID := result.InsertedID.(primitive.ObjectID)
	log.Printf("✅ Kullanıcı oluşturuldu: %s (ID: %s)", newUser.Username, userID.Hex())

	// Email doğrulama token'ı ve mail
	verificationToken, err := services.GenerateEmailVerificationToken(userID)
	if err != nil {
		log.Printf("⚠️ Email doğrulama token'ı oluşturulamadı: %v", err)
		c.JSON(http.StatusCreated, gin.H{
			"message": "Kayıt başarılı ancak doğrulama e-postası gönderilemedi",
			"user_id": userID.Hex(),
		})
		return
	}

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", frontendURL, verificationToken)
	log.Printf("🔗 Doğrulama linki: %s", verificationLink)

	if err := services.SendVerificationEmail(c.Request.Context(), userID, verificationToken); err != nil {
		log.Printf("❌ E-posta gönderme hatası: %v", err)
		c.JSON(http.StatusCreated, gin.H{
			"message": "Kayıt başarılı ancak doğrulama e-postası gönderilemedi",
			"user_id": userID.Hex(),
		})
		return
	}

	log.Printf("✅ Doğrulama e-postası gönderildi: %s", newUser.Email)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Kayıt başarılı! E-posta adresinize doğrulama bağlantısı gönderildi.",
		"user_id": userID.Hex(),
	})
}
