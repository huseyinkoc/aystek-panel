package utils

import "testing"

func TestGenerateSlug(t *testing.T) {
	title := "Hello, World! 2024"
	expected := "hello-world-2024"
	result := GenerateSlug(title)

	if result != expected {
		t.Errorf("GenerateSlug failed: expected %s, got %s", expected, result)
	}
}
