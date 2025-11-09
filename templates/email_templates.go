package templates

import (
    "fmt"
    "time"
)

// VerificationEmailTemplate returns HTML template for email verification
func VerificationEmailTemplate(username, verificationLink string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-posta Doğrulama</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); min-height: 100vh;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="margin: 0; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 600;">✉️ E-posta Doğrulama</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="margin: 0 0 20px; color: #1a202c; font-size: 24px; font-weight: 600;">Merhaba %s! 👋</h2>
                            <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
                                AYSTEK Yönetim Paneli'ne hoş geldiniz! Hesabınızı aktifleştirmek için e-posta adresinizi doğrulamanız gerekmektedir.
                            </p>
                            <p style="margin: 0 0 30px; color: #4a5568; font-size: 16px; line-height: 1.6;">
                                Aşağıdaki butona tıklayarak e-posta adresinizi doğrulayabilirsiniz:
                            </p>
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding: 20px 0;">
                                        <a href="%s" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);">
                                            E-postamı Doğrula
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 30px 0 0; color: #718096; font-size: 14px; line-height: 1.6;">
                                Buton çalışmıyorsa aşağıdaki bağlantıyı kopyalayıp tarayıcınıza yapıştırabilirsiniz:
                            </p>
                            <p style="margin: 10px 0 0; padding: 15px; background: #f7fafc; border-radius: 8px; word-break: break-all;">
                                <a href="%s" style="color: #667eea; text-decoration: none; font-size: 13px;">%s</a>
                            </p>
                            <div style="margin: 30px 0 0; padding: 20px; background: #fff5f5; border-left: 4px solid #fc8181; border-radius: 8px;">
                                <p style="margin: 0; color: #742a2a; font-size: 14px; line-height: 1.6;">
                                    ⚠️ <strong>Önemli:</strong> Bu bağlantı 24 saat geçerlidir. Eğer bu isteği siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px; background: #f7fafc; border-top: 1px solid #e2e8f0; text-align: center;">
                            <p style="margin: 0 0 10px; color: #718096; font-size: 14px;">AYSTEK Mühendislik © %d</p>
                            <p style="margin: 0; color: #a0aec0; font-size: 12px;">Bu otomatik bir e-postadır, lütfen yanıtlamayın.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, username, verificationLink, verificationLink, verificationLink, time.Now().Year())
}

// PasswordResetEmailTemplate returns HTML template for password reset
func PasswordResetEmailTemplate(username, resetLink string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Şifre Sıfırlama</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); min-height: 100vh;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="margin: 0; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 600;">🔐 Şifre Sıfırlama</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="margin: 0 0 20px; color: #1a202c; font-size: 24px; font-weight: 600;">Merhaba %s! 👋</h2>
                            <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
                                Hesabınız için bir şifre sıfırlama talebi aldık. Şifrenizi sıfırlamak için aşağıdaki butona tıklayın:
                            </p>
                            <table width="100%%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding: 20px 0;">
                                        <a href="%s" style="display: inline-block; background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); color: white; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 12px rgba(245, 87, 108, 0.4);">
                                            Şifremi Sıfırla
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin: 30px 0 0; color: #718096; font-size: 14px; line-height: 1.6;">
                                Buton çalışmıyorsa aşağıdaki bağlantıyı kopyalayıp tarayıcınıza yapıştırabilirsiniz:
                            </p>
                            <p style="margin: 10px 0 0; padding: 15px; background: #f7fafc; border-radius: 8px; word-break: break-all;">
                                <a href="%s" style="color: #f5576c; text-decoration: none; font-size: 13px;">%s</a>
                            </p>
                            <div style="margin: 30px 0 0; padding: 20px; background: #fff5f5; border-left: 4px solid #fc8181; border-radius: 8px;">
                                <p style="margin: 0; color: #742a2a; font-size: 14px; line-height: 1.6;">
                                    ⚠️ <strong>Önemli:</strong> Bu bağlantı 30 dakika geçerlidir. Eğer bu isteği siz yapmadıysanız, lütfen derhal destek ekibimizle iletişime geçin.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px; background: #f7fafc; border-top: 1px solid #e2e8f0; text-align: center;">
                            <p style="margin: 0 0 10px; color: #718096; font-size: 14px;">AYSTEK Mühendislik © %d</p>
                            <p style="margin: 0; color: #a0aec0; font-size: 12px;">Bu otomatik bir e-postadır, lütfen yanıtlamayın.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, username, resetLink, resetLink, resetLink, time.Now().Year())
}

// WelcomeEmailTemplate returns HTML template for welcome email (opsiyonel)
func WelcomeEmailTemplate(username string) string {
    return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hoş Geldiniz</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #11998e 0%%, #38ef7d 100%%); min-height: 100vh;">
    <table width="100%%" cellpadding="0" cellspacing="0" style="margin: 0; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #11998e 0%%, #38ef7d 100%%); padding: 40px 30px; text-align: center;">
                            <h1 style="margin: 0; color: white; font-size: 28px; font-weight: 600;">🎉 Hoş Geldiniz!</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="margin: 0 0 20px; color: #1a202c; font-size: 24px; font-weight: 600;">Merhaba %s! 🚀</h2>
                            <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
                                Hesabınız başarıyla onaylandı! Artık AYSTEK Yönetim Paneli'nin tüm özelliklerinden yararlanabilirsiniz.
                            </p>
                            <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
                                Platformumuzu kullanırken herhangi bir sorunla karşılaşırsanız, destek ekibimizle iletişime geçmekten çekinmeyin.
                            </p>
                            <div style="margin: 30px 0 0; padding: 20px; background: #f0fdf4; border-left: 4px solid #4ade80; border-radius: 8px;">
                                <p style="margin: 0; color: #14532d; font-size: 14px; line-height: 1.6;">
                                    💡 <strong>İpucu:</strong> Profil ayarlarınızdan bilgilerinizi güncelleyebilir ve güvenlik tercihlerinizi düzenleyebilirsiniz.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px; background: #f7fafc; border-top: 1px solid #e2e8f0; text-align: center;">
                            <p style="margin: 0 0 10px; color: #718096; font-size: 14px;">AYSTEK Mühendislik © %d</p>
                            <p style="margin: 0; color: #a0aec0; font-size: 12px;">Bu otomatik bir e-postadır, lütfen yanıtlamayın.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`, username, time.Now().Year())
}