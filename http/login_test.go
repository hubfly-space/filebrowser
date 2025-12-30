package fbhttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage/bolt"
	"github.com/filebrowser/filebrowser/v2/users"
	"github.com/stretchr/testify/assert"
)

func setup(t *testing.T) (*data, func()) {
	dbPath := filepath.Join(t.TempDir(), "db")
	db, err := storm.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	storage, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("failed to get storage: %v", err)
	}

	user := &users.User{
		ID:       1,
		Username: "test",
		Password: "password",
	}

	err = storage.Users.Save(user)
	if err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	server := &settings.Server{}
	d := &data{
		store:  storage,
		server: server,
		user:   user,
	}

	return d, func() {
		err := db.Close()
		assert.NoError(t, err)
	}
}

func TestCreateLoginTokenHandler(t *testing.T) {
	// setup
	data, cleanup := setup(t)
	defer cleanup()

	ott := NewOTTStore()
	handler := createLoginTokenHandler(ott)

	// execute
	req, err := http.NewRequest("POST", "/api/login/token", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	status, err := handler(rr, req, data)
	assert.NoError(t, err)
	assert.Equal(t, 0, status)

	// assert
	var resp map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Contains(t, resp, "url")
	assert.Contains(t, resp["url"], "/login?ott=")
}

func TestRedeemLoginTokenHandler(t *testing.T) {
	// setup
	data, cleanup := setup(t)
	defer cleanup()

	ott := NewOTTStore()
	// The JWT content doesn't matter for this test, only that it exists.
	signedToken, err := getSignedToken(data, data.user, time.Minute)
	assert.NoError(t, err)

	ottToken, err := ott.Set(signedToken, 1*time.Minute)
	assert.NoError(t, err)

	body, err := json.Marshal(map[string]string{"ott": ottToken})
	assert.NoError(t, err)
	req, err := http.NewRequest("POST", "/api/login/redeem", bytes.NewBuffer(body))
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := redeemLoginTokenHandler(ott)

	// execute
	status, err := handler(rr, req, data)
	assert.NoError(t, err)
	assert.Equal(t, 0, status)

	// assert
	assert.Equal(t, signedToken, rr.Body.String())
}

func TestRedeemLoginTokenHandler_expired(t *testing.T) {
	// setup
	data, cleanup := setup(t)
	defer cleanup()

	ott := NewOTTStore()
	// The JWT content doesn't matter for this test.
	signedToken, err := getSignedToken(data, data.user, time.Minute)
	assert.NoError(t, err)

	ottToken, err := ott.Set(signedToken, -1*time.Minute)
	assert.NoError(t, err)

	body, err := json.Marshal(map[string]string{"ott": ottToken})
	assert.NoError(t, err)
	req, err := http.NewRequest("POST", "/api/login/redeem", bytes.NewBuffer(body))
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := redeemLoginTokenHandler(ott)

	// execute
	status, err := handler(rr, req, data)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)
}