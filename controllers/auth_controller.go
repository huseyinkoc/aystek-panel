package controllers

import (
	"admin-panel/configs"
	"admin-panel/middlewares"
	"admin-panel/services"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

	// 1) Kullanıcının geçerli access token’ı var mı? Varsa aynısını döndür.
	if tokenStr, _, err := services.GetValidAccessToken(c.Request.Context(), user.ID.Hex()); err == nil && tokenStr != "" {
		csrf := middlewares.GetStoredCSRFToken(user.Username) // eğer yoksa, aşağıda yeniden üretilecek
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

	// 2) Geçerli token yoksa — yeni access + refresh oluştur
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

	// Refresh token
	refreshToken := primitive.NewObjectID().Hex()
	refreshExp := time.Now().Add(configs.GetRefreshExpiry())
	_ = services.SaveRefreshToken(c.Request.Context(), user.ID.Hex(), refreshToken, refreshExp)

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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}
	if err := services.CheckPassword(user.Password, input.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Hatalı şifre"})
		return
	}

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
	refreshExp := time.Now().Add(configs.GetRefreshExpiry())
	_ = services.SaveRefreshToken(c.Request.Context(), user.ID.Hex(), refreshToken, refreshExp)

	csrfToken, _ := middlewares.GenerateCSRFToken()
	middlewares.StoreCSRFToken(user.Email, csrfToken)

	c.JSON(http.StatusOK, gin.H{
		"token":         accessToken,
		"csrf_token":    csrfToken,
		"refresh_token": refreshToken,
		"message":       "Giriş başarılı",
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

	user, err := services.GetUserByPhone(input.PhoneNumber)
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
	refreshExp := time.Now().Add(configs.GetRefreshExpiry())
	_ = services.SaveRefreshToken(c.Request.Context(), user.ID.Hex(), refreshToken, refreshExp)

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

	// Yeni access token
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

	// Eski access kayıtlarını temizlemek istersen (opsiyonel):
	_ = services.DeleteAccessTokens(c.Request.Context(), userID)
	_ = services.SaveAccessToken(c.Request.Context(), userID, newAccess, accessExp)

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
	// AuthMiddleware'de c.Set("userID", claims.UserID) ve c.Set("username", claims.Username) olmalı
	userID := c.GetString("userID")
	username := c.GetString("username")

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// 1️⃣ Access + Refresh token kayıtlarını MongoDB'den sil
	if err := services.DeleteRefreshTokens(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Refresh token silinemedi"})
		return
	}
	if err := services.DeleteAccessTokens(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Access token silinemedi"})
		return
	}

	// 2️⃣ CSRF token'ı bellekteki map'ten sil
	if username != "" {
		middlewares.DeleteCSRFToken(username)
	}

	// 3️⃣ Başarılı yanıt dön
	c.JSON(http.StatusOK, gin.H{
		"message": "Çıkış başarılı, tüm tokenlar temizlendi",
	})
}

// SendVerificationEmailHandler sends a verification email to the user
// @Summary Send verification email
// @Description Sends a verification email to a specific user
// @Tags Authentication
// @Param userID path string true "User ID"
// @Success 200 {object} map[string]interface{} "Verification email sent"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 500 {object} map[string]interface{} "Failed to send verification email"
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

	err = services.SendVerificationEmail(c.Request.Context(), objectID, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// VerifyEmailHandler verifies a user's email
// @Summary Verify email
// @Description Verifies a user's email using a token
// @Tags Authentication
// @Param token query string true "Verification token"
// @Success 200 {object} map[string]interface{} "Email verified successfully"
// @Failure 400 {object} map[string]interface{} "Invalid or expired token"
// @Router /svc/auth/verify-email [get]
func VerifyEmailHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	err := services.VerifyEmailToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// RequestPasswordResetHandler handles password reset requests
// @Summary Request password reset
// @Description Sends a password reset email to the user
// @Tags Authentication
// @Accept json
// @Produce json
// @Param email body models.RequestPasswordReset true "User email"
// @Success 200 {object} map[string]interface{} "Password reset email sent"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 404 {object} map[string]interface{} "Email not found"
// @Failure 500 {object} map[string]interface{} "Failed to send password reset email"
// @Router /svc/auth/request-password-reset [post]
func RequestPasswordResetHandler(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Kullanıcıyı email ile bulun
	userID, err := services.GetUserIDByEmail(c.Request.Context(), request.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Email not found"})
		return
	}

	// Reset token oluştur
	token, err := services.GeneratePasswordResetToken(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate password reset token"})
		return
	}

	resetURL := "http://localhost:8080/auth/reset-password?token=" + token
	subject := "Password Reset Request"
	body := "Click the link to reset your password: " + resetURL

	err = services.SendEmail([]string{request.Email}, subject, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}

// ResetPasswordHandler resets a user's password
// @Summary Reset password
// @Description Resets a user's password using a valid reset token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param token query string true "Password reset token"
// @Param request body models.ResetPasswordRequest true "New password"
// @Success 200 {object} map[string]interface{} "Password updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload or token"
// @Failure 500 {object} map[string]interface{} "Failed to update password"
// @Router /svc/auth/reset-password [post]
func ResetPasswordHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	var request struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Token'ı doğrula
	userID, err := services.VerifyPasswordResetToken(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Şifreyi güncelle
	err = services.UpdateUserPassword(c.Request.Context(), userID, request.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Token'ı sil
	_ = services.DeletePasswordResetToken(c.Request.Context(), token)

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}
