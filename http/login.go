package http

import (
	"encoding/json"
	"net/http"
	"path"
	"time"

	"github.com/filebrowser/filebrowser/v2/users"
	"github.com/golang-jwt/jwt/v5"
)

// The new createLoginTokenHandler, following the handleFunc pattern.
// It must be wrapped by withUser to have access to d.user.
func createLoginTokenHandler(ott *ottStore) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		// Get a new JWT for the current user.
		token, err := getSignedToken(d, d.user, d.server.GetTokenExpirationTime(DefaultTokenExpirationTime))
		if err != nil {
			return http.StatusInternalServerError, err
		}

		// Create a new one-time token.
		oneTimeToken, err := ott.Set(token, 5*time.Minute)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		// Return the URL containing the one-time token.
		response := map[string]string{
			"url": path.Join(d.server.BaseURL, "/login?ott="+oneTimeToken),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return http.StatusInternalServerError, err
		}
		return 0, nil
	}
}

// The new redeemLoginTokenHandler, following the handleFunc pattern.
// It is a public handler.
func redeemLoginTokenHandler(ott *ottStore) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		// We expect the one-time token to be in the request body as JSON.
		var body struct {
			OTT string `json:"ott"`
		}

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return http.StatusBadRequest, err
		}

		if body.OTT == "" {
			return http.StatusBadRequest, nil
		}

		// Get the real JWT from the one-time token.
		jwt, ok := ott.Get(body.OTT)
		if !ok {
			return http.StatusUnauthorized, nil
		}

		// Return the real JWT.
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(jwt)); err != nil {
			return http.StatusInternalServerError, err
		}

		return 0, nil
	}
}

// getSignedToken is a helper function adapted from printToken. Instead of
// writing to the response, it returns the signed token as a string.
func getSignedToken(d *data, user *users.User, tokenExpirationTime time.Duration) (string, error) {
	claims := &authToken{
		User: userInfo{
			ID:           user.ID,
			Locale:       user.Locale,
			ViewMode:     user.ViewMode,
			SingleClick:  user.SingleClick,
			Perm:         user.Perm,
			LockPassword: user.LockPassword,
			Commands:     user.Commands,
			HideDotfiles: user.HideDotfiles,
			DateFormat:   user.DateFormat,
			Username:     user.Username,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpirationTime)),
			Issuer:    "File Browser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(d.settings.Key)
}