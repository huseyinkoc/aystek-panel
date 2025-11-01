package services

import (
	"admin-panel/configs"
	"crypto/tls"
	"fmt"
	"net/smtp"
)

var emailConfig configs.EmailConfig

// InitEmailService initializes the email service configuration
func InitEmailService(config configs.EmailConfig) {
	emailConfig = config
}

// SendEmail dynamically handles SSL/TLS settings
func SendEmail(to []string, subject string, body string) error {
	addr := fmt.Sprintf("%s:%d", emailConfig.Host, emailConfig.Port)
	auth := smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.Host)

	msg := []byte(fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body))

	// TLS veya SSL bağlantısını kontrol et
	if emailConfig.UseTLS {
		// STARTTLS için bağlantı aç ve başlat
		conn, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		if err := conn.StartTLS(&tls.Config{ServerName: emailConfig.Host}); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}

		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return sendEmail(conn, msg, to)
	} else if emailConfig.UseSSL {
		// SSL bağlantısı için doğrudan TLS kullan
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         emailConfig.Host,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, emailConfig.Host)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return sendEmail(client, msg, to)
	} else {
		// Normal SMTP bağlantısı
		client, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer client.Close()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return sendEmail(client, msg, to)
	}
}

// Helper function to send email using an SMTP client
func sendEmail(client *smtp.Client, msg []byte, to []string) error {
	if err := client.Mail(emailConfig.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get writer: %w", err)
	}

	_, err = wc.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write email body: %w", err)
	}

	err = wc.Close()
	if err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return client.Quit()
}
