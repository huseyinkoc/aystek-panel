package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"plugin"
	"testing"
)

// Test Plugin Upload
func TestUploadPlugin(t *testing.T) {
	// Örnek eklenti dosyasının yolu
	pluginPath := "./test_plugins/myplugin.so"

	// Kontrol: Dosya mevcut mu?
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		t.Fatalf("Plugin file does not exist: %v", pluginPath)
	}

	// Kontrol: Dosya uzantısı .so mu?
	if filepath.Ext(pluginPath) != ".so" {
		t.Fatalf("Invalid file format: %v. Expected .so", filepath.Ext(pluginPath))
	}

	t.Log("Plugin upload test passed")
}

// Test Plugin Integrity
func TestPluginIntegrity(t *testing.T) {
	pluginPath := "./test_plugins/myplugin.so"
	expectedHash := "expected_sha256_hash_value"

	// Hash kontrolü
	isValid, err := VerifyPluginIntegrity(pluginPath, expectedHash)
	if err != nil {
		t.Fatalf("Error verifying plugin integrity: %v", err)
	}

	if !isValid {
		t.Fatalf("Plugin integrity check failed for: %v", pluginPath)
	}

	t.Log("Plugin integrity test passed")
}

// Test Plugin Activation
func TestActivatePlugin(t *testing.T) {
	pluginPath := "./test_plugins/myplugin.so"

	// Eklentiyi yükle
	plug, err := plugin.Open(pluginPath)
	if err != nil {
		t.Fatalf("Failed to load plugin: %v", err)
	}

	// Eklentinin Initialize fonksiyonunu bul
	initFunc, err := plug.Lookup("Initialize")
	if err != nil {
		t.Fatalf("Failed to find Initialize function: %v", err)
	}

	// Fonksiyonu çağır
	initFunc.(func())()

	t.Log("Plugin activation test passed")
}

// Helper: Verify Plugin Integrity
func VerifyPluginIntegrity(filePath string, expectedHash string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}

	actualHash := fmt.Sprintf("%x", hash.Sum(nil))
	return actualHash == expectedHash, nil
}
