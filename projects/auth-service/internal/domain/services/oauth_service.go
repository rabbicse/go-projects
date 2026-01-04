package services

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/authorization"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	"github.com/rabbicse/auth-service/internal/domain/repositories"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
	"github.com/rabbicse/auth-service/pkg/errors"
)

// OAuthService coordinates operations between aggregates
type OAuthService struct {
	clientRepo        repositories.ClientRepository
	authorizationRepo repositories.AuthorizationRepository
	tokenRepo         repositories.TokenRepository
	clientFactory     *client.ClientFactory
	authFactory       *authorization.AuthorizationFactory
	tokenFactory      *token.TokenFactory
}

func NewOAuthService(
	clientRepo repositories.ClientRepository,
	authorizationRepo repositories.AuthorizationRepository,
	tokenRepo repositories.TokenRepository,
) *OAuthService {
	return &OAuthService{
		clientRepo:        clientRepo,
		authorizationRepo: authorizationRepo,
		tokenRepo:         tokenRepo,
		clientFactory:     client.NewClientFactory(),
		authFactory:       authorization.NewAuthorizationFactory(),
		tokenFactory:      token.NewTokenFactory(),
	}
}

// CreateAuthorization creates a new authorization for a client/user
func (s *OAuthService) CreateAuthorization(
	clientID string,
	userID string,
	redirectURI string,
	requestedScopes []string,
) (*authorization.Authorization, error) {

	// Get client aggregate
	clientAgg, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return nil, errors.WrapDomainError(err, "invalid_client", "Client not found")
	}

	// Validate client is active
	if !clientAgg.Active {
		return nil, errors.NewDomainError("invalid_client", "Client is not active")
	}

	// Validate redirect URI
	if err := clientAgg.ValidateRedirectURI(redirectURI); err != nil {
		return nil, errors.NewDomainError("invalid_request", "Invalid redirect URI")
	}

	// Validate requested scopes
	if err := clientAgg.ValidateScopes(requestedScopes); err != nil {
		return nil, errors.NewDomainError("invalid_scope", err.Error())
	}

	// Create authorization aggregate
	auth, err := authorization.NewAuthorization(
		clientID,
		userID,
		redirectURI,
		requestedScopes,
	)
	if err != nil {
		return nil, errors.NewDomainError("server_error", "Failed to create authorization")
	}

	// Save authorization
	if err := s.authorizationRepo.Save(auth); err != nil {
		return nil, errors.NewDomainError("server_error", "Failed to save authorization")
	}

	return auth, nil
}

// ExchangeAuthorizationForTokens exchanges an authorization code for tokens
func (s *OAuthService) ExchangeAuthorizationForTokens(
	code string,
	clientID string,
	clientSecret string,
	redirectURI string,
) (*token.Token, error) {

	// Get authorization aggregate
	auth, err := s.authorizationRepo.FindByCode(code)
	if err != nil {
		return nil, errors.NewDomainError("invalid_grant", "Invalid authorization code")
	}

	// Validate authorization
	if err := auth.Validate(); err != nil {
		return nil, errors.NewDomainError("invalid_grant", err.Error())
	}

	// Verify client matches
	if err := auth.VerifyClient(clientID); err != nil {
		return nil, errors.NewDomainError("invalid_grant", err.Error())
	}

	// Verify redirect URI matches
	if err := auth.VerifyRedirectURI(redirectURI); err != nil {
		return nil, errors.NewDomainError("invalid_grant", err.Error())
	}

	// Get client for authentication
	clientAgg, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return nil, errors.NewDomainError("invalid_client", "Client not found")
	}

	// Authenticate client (only for confidential clients)
	if err := clientAgg.Authenticate(clientSecret); err != nil {
		return nil, errors.NewDomainError("invalid_client", "Client authentication failed")
	}

	// Mark authorization as used
	if err := auth.MarkAsUsed(); err != nil {
		return nil, errors.NewDomainError("invalid_grant", err.Error())
	}

	// Save updated authorization
	if err := s.authorizationRepo.Save(auth); err != nil {
		return nil, errors.NewDomainError("server_error", "Failed to update authorization")
	}

	// Create token aggregate
	tokenAgg, err := token.NewToken(
		clientID,
		auth.UserID().Value(),
		auth.Scopes(),
		valueobjects.TokenType{Value: "Bearer"},
		time.Hour, // Access token lifetime
		true,      // Include refresh token
	)
	if err != nil {
		return nil, errors.NewDomainError("server_error", "Failed to create tokens")
	}

	// Save tokens
	if err := s.tokenRepo.SaveAccessToken(tokenAgg); err != nil {
		return nil, errors.NewDomainError("server_error", "Failed to save access token")
	}

	if tokenAgg.RefreshToken() != nil {
		if err := s.tokenRepo.SaveRefreshToken(tokenAgg); err != nil {
			return nil, errors.NewDomainError("server_error", "Failed to save refresh token")
		}
	}

	return tokenAgg, nil
}

// ValidateAccessToken validates an access token
func (s *OAuthService) ValidateAccessToken(accessToken string) (*token.Token, error) {
	tokenAgg, err := s.tokenRepo.FindAccessToken(accessToken)
	if err != nil {
		return nil, errors.NewDomainError("invalid_token", "Access token not found")
	}

	if err := tokenAgg.Validate(); err != nil {
		return nil, errors.NewDomainError("invalid_token", err.Error())
	}

	return tokenAgg, nil
}

// RefreshAccessToken exchanges a refresh token for a new access token
func (s *OAuthService) RefreshAccessToken(
	refreshToken string,
	clientID string,
	clientSecret string,
	requestedScopes []string,
) (*token.Token, error) {

	// Get token by refresh token
	tokenAgg, err := s.tokenRepo.FindRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.NewDomainError("invalid_grant", "Invalid refresh token")
	}

	// Validate refresh token
	if err := tokenAgg.Validate(); err != nil {
		return nil, errors.NewDomainError("invalid_grant", err.Error())
	}

	// Verify client matches
	if tokenAgg.ClientID().Value() != clientID {
		return nil, errors.NewDomainError("invalid_client", "Refresh token issued to different client")
	}

	// Get client for authentication
	clientAgg, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return nil, errors.NewDomainError("invalid_client", "Client not found")
	}

	// Authenticate client
	if err := clientAgg.Authenticate(clientSecret); err != nil {
		return nil, errors.NewDomainError("invalid_client", "Client authentication failed")
	}

	// Refresh the token
	newToken, err := tokenAgg.Refresh(requestedScopes)
	if err != nil {
		return nil, errors.NewDomainError("invalid_grant", err.Error())
	}

	// Save new token
	if err := s.tokenRepo.SaveAccessToken(newToken); err != nil {
		return nil, errors.NewDomainError("server_error", "Failed to save new access token")
	}

	// Save new refresh token
	if newToken.RefreshToken() != nil {
		if err := s.tokenRepo.SaveRefreshToken(newToken); err != nil {
			return nil, errors.NewDomainError("server_error", "Failed to save new refresh token")
		}
	}

	// Revoke old token
	if err := s.tokenRepo.RevokeAccessToken(tokenAgg.AccessToken().Value); err != nil {
		// Log error but continue
		// In production, use proper logging
	}

	return newToken, nil
}
