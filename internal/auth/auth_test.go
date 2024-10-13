package auth

import (
	"fmt"
	"net/http"
	"testing"
)

func TestGetAPIKey_NoHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "www.sample.com", nil)
	header := req.Header

	_, err := GetAPIKey(header)
	if err == nil {
		t.Log("Expected error when no header provided")
		t.Fail()
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "www.sample.com", nil)
	header := req.Header

	header.Add("Authorization", "ApiKey")

	_, err := GetAPIKey(header)
	if err == nil {
		t.Log("Expected error when no header is malformed")
		t.Fail()
	}
}

func TestGetAPIKey_HeaderNotApiKey(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "www.sample.com", nil)
	header := req.Header

	header.Add("Authorization", "NotApiKey MyApiKey")

	_, err := GetAPIKey(header)
	if err == nil {
		t.Log("Expected error when 'ApiKey' is not first token in header")
		t.Fail()
	}
}

func TestGetAPIKey_MalformedKey(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "www.sample.com", nil)
	header := req.Header

	header.Add("Authorization", "NotApiKey My ApiKey")

	_, err := GetAPIKey(header)
	if err == nil {
		t.Log("Expected error when Api key is multi-token")
		t.Fail()
	}
}

func TestGetAPIKey_ReturnsKey(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "www.sample.com", nil)
	header := req.Header

	apiKey := "MyAPIKey"
	headerText := fmt.Sprintf("ApiKey %s", apiKey)

	header.Add("Authorization", headerText)

	key, err := GetAPIKey(header)
	if err != nil {
		t.Logf("Expected no error not: %s", err)
		t.Fail()
	}

	if key != apiKey {
		t.Logf("Expected %v to equal %v", key, apiKey)
		t.Fail()
	}
}
