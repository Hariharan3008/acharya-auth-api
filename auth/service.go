package auth

import (
	"acharya-auth-api/storage"
	"acharya-auth-api/errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AuthService struct {
	users  storage.User
	tokens storage.Token
	jwtSecret  []byte
}

// CustomClaims contains our custom JWT claims
type CustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func NewAuthService(users storage.User, tokens storage.Token) *AuthService {
	return &AuthService{
		users:  users,
		tokens: tokens,
		jwtSecret:  []byte("acharya-key-3008"),
	}
}

func (s *AuthService) SignUp(email, password string) error {
	// Check if user already exists
	if s.users.Exists(email) {
		return errors.ErrEmailExists
	}

	s.users.Save(email, password)
	return nil
}

func (s *AuthService) SignIn(email, password string) (*TokenResponse, error) {
	// Verify user credentials
	storedPassword, err := s.users.Get(email)
	if err != nil || storedPassword != password { 
		return nil, errors.ErrInvalidCredentials
	}

	// Generate tokens
	accessToken, err := s.generateToken(email, 15*time.Minute)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateToken(email, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	s.tokens.Save(accessToken, refreshToken)

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    15 * 60,
	}, nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*TokenResponse, error) {
	// Validate refresh token
	claims, err := s.validateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	// Check if refresh token exists
	oldAccess, exists := s.tokens.GetByRefresh(refreshToken)
	if !exists {
		return nil, errors.ErrInvalidToken
	}

	// Revoke old tokens
	s.tokens.Revoke(oldAccess)

	// Generate new tokens
	newAccess, err := s.generateToken(claims.Email, 15*time.Minute)
	if err != nil {
		return nil, err
	}

	newRefresh, err := s.generateToken(claims.Email, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	s.tokens.Save(newAccess, newRefresh)

	return &TokenResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
		ExpiresIn:    15 * 60,
	}, nil
}

func (s *AuthService) RevokeToken(token string) error {
	if !s.tokens.Exists(token) {
		return errors.ErrInvalidToken
	}
	s.tokens.Revoke(token)
	return nil
}

func (s *AuthService) ValidateToken(token string) (string, error) {
	claims, err := s.validateToken(token)
	if err != nil {
		return "", err
	}

	if !s.tokens.Exists(token) {
		return "", errors.ErrTokenRevoked
	}

	return claims.Email, nil
}

// Helper method to generate JWT tokens
func (s *AuthService) generateToken(email string, expiresIn time.Duration) (string, error) {
	claims := CustomClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// Helper method to validate JWT tokens
func (s *AuthService) validateToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.ErrTokenExpired
			}
		}
		return nil, errors.ErrInvalidToken
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.ErrInvalidToken
}