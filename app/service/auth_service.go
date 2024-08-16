package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/atrariksa/kenalan-auth/app/repository"
	"github.com/atrariksa/kenalan-auth/app/util"
	"github.com/redis/go-redis/v9"
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
		return "", errors.New(util.ErrInternalError)
	}

	err = as.Repo.StoreToken(ctx, fmt.Sprintf(tokenKey, email), token)
	if err != nil {
		log.Println(err)
		return "", errors.New(util.ErrInternalError)
	}

	return token, nil
}

func (as *AuthService) ValidateToken(ctx context.Context, token string) (bool, string, error) {
	email, err := util.VerifyToken(token)
	if err != nil {
		if err.Error() == util.ErrInvalidToken {
			return false, "", err
		}
		log.Println(err)
		return false, "", err
	}

	tokenFromRedis, err := as.Repo.GetToken(ctx, fmt.Sprintf(tokenKey, email))
	if err != nil && err != redis.Nil {
		log.Println(err)
		return false, "", errors.New(util.ErrInternalError)
	}

	if token != tokenFromRedis {
		return false, "", errors.New(util.ErrInvalidToken)
	}

	return true, email, nil
}
