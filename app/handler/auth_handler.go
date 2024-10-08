package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	pb "github.com/atrariksa/kenalan-auth/app/internal/grpc_auth_server"
	"github.com/atrariksa/kenalan-auth/app/repository"
	"github.com/atrariksa/kenalan-auth/app/service"
	"github.com/atrariksa/kenalan-auth/app/util"
	"github.com/atrariksa/kenalan-auth/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type authServiceServer struct {
	pb.UnimplementedAuthServiceServer
	authService service.IAuthService
}

func GetAuthServiceServer(svc service.IAuthService) *authServiceServer {
	return &authServiceServer{
		authService: svc,
	}
}

func (s authServiceServer) GetToken(ctx context.Context, req *pb.GetTokenRequest) (*pb.GetTokenResponse, error) {
	if req.Email == "" {
		return nil, status.Error(util.CodeInvalidEmail, util.ErrInvalidEmail)
	}

	token, err := s.authService.GenerateToken(ctx, req.Email)
	if err != nil {
		return nil, errors.New(util.ErrInternalError)
	}

	response := pb.GetTokenResponse{
		Code:  0000,
		Token: token,
	}

	return &response, nil
}

func (s authServiceServer) IsTokenValid(ctx context.Context, req *pb.IsTokenValidRequest) (*pb.IsTokenValidResponse, error) {
	if req.Token == "" {
		return nil, status.Error(util.CodeInvalidToken, util.ErrInvalidToken)
	}

	isTokenValid, email, err := s.authService.ValidateToken(ctx, req.Token)
	if err != nil {
		if err.Error() == util.ErrInvalidToken {
			return nil, status.Error(util.CodeInvalidToken, util.ErrInvalidToken)
		}
		return nil, errors.New(util.ErrInternalError)
	}

	response := pb.IsTokenValidResponse{
		Code:         0000,
		IsTokenValid: isTokenValid,
		Email:        email,
	}
	return &response, nil
}

func SetupServer() {
	fmt.Println("---Auth Service---")

	cfg := config.GetConfig()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ServerConfig.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	rc := util.GetRedisClient(cfg)
	authRepo := repository.NewAuthRepository(rc)
	authService := service.NewAuthService(authRepo)

	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, GetAuthServiceServer(authService))
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
