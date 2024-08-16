package repository

import (
	"context"

	"github.com/atrariksa/kenalan-auth/app/util"
	"github.com/redis/go-redis/v9"
)

type IAuthRepository interface {
	StoreToken(ctx context.Context, key string, token string) error
	GetToken(ctx context.Context, key string) (string, error)
}

type AuthRepository struct {
	RC *redis.Client
}

func NewAuthRepository(rc *redis.Client) *AuthRepository {
	return &AuthRepository{
		RC: rc,
	}
}

func (ar *AuthRepository) StoreToken(ctx context.Context, key string, token string) error {
	return ar.RC.Set(ctx, key, token, util.TokenDuration).Err()
}

func (ar *AuthRepository) GetToken(ctx context.Context, key string) (string, error) {
	return ar.RC.Get(ctx, key).Result()
}
