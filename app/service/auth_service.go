package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/atrariksa/kenalan-auth/app/repository"
	"github.com/atrariksa/kenalan-auth/app/util"
)

var tokenKey = "token:%s"

type IAuthService interface {
	GenerateToken(ctx context.Context, email string) (string, error)
	ValidateToken(ctx context.Context, token string) (bool, string, error)
}

type AuthService struct {
	Repo repository.IAuthRepository
}

func NewAuthService(repo repository.IAuthRepository) *AuthService {
	return &AuthService{
		Repo: repo,
	}
}

func (as *AuthService) GenerateToken(ctx context.Context, email string) (string, error) {
	token, err := util.GenerateToken(email)
	if err != nil {
		log.Println(err)
		return "", errors.New("internal error")
	}

	err = as.Repo.StoreToken(ctx, fmt.Sprintf(tokenKey, email), token)
	if err != nil {
		log.Println(err)
		return "", errors.New("internal error")
	}

	return token, nil
}

func (as *AuthService) ValidateToken(ctx context.Context, token string) (bool, string, error) {
	email, err := util.VerifyToken(token)
	if err != nil {
		log.Println(err)
		return false, "", err
	}

	tokenFromRedis, err := as.Repo.GetToken(ctx, fmt.Sprintf(tokenKey, email))
	if err != nil {
		log.Println(err)
		return false, "", err
	}

	if token != tokenFromRedis {
		return false, "", errors.New("invalid token")
	}
	return true, email, nil
}
