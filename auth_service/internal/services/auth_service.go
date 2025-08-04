package services

import (
	"chat-app/auth_service/internal/middleware"
	"chat-app/auth_service/internal/models"
	"chat-app/auth_service/utils/database"
	pb "chat-app/proto/auth"
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
}

func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	collection := database.GetUsersCollection()
	var existingUser models.User
	err := collection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&existingUser)
	if err == nil {
		return nil, errors.New("User already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}

	user.ID = result.InsertedID.(primitive.ObjectID)

	accessToken, err := middleware.GenerateAccessToken(user.ID.Hex(), user.Username, user.Email)
	if err != nil {
		return nil, err
	}
	refreshToken, err := middleware.GenerateRefreshToken(user.ID.Hex())
	if err != nil {
		return nil, err
	}
	refreshTokenDoc := models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
	database.GetRefreshTokensCollection().InsertOne(ctx, refreshTokenDoc)

	return &pb.RegisterResponse{
		User: &pb.User{
			Id:        user.ID.Hex(),
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Unix(),
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	collection := database.GetUsersCollection()
	var user models.User
	err := collection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		return nil, errors.New("Invalid creadentials")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, errors.New("Invalid creadentials")
	}
	accessToken, err := middleware.GenerateAccessToken(user.ID.Hex(), user.Username, user.Email)
	if err != nil {
		return nil, err
	}
	refreshToken, err := middleware.GenerateRefreshToken(user.ID.Hex())
	if err != nil {
		return nil, err
	}
	refreshTokenDoc := models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
	database.GetRefreshTokensCollection().InsertOne(ctx, refreshTokenDoc)
	return &pb.LoginResponse{
		User: &pb.User{
			Id:        user.ID.Hex(),
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Unix()},
		AccessToken:  accessToken,
		RefreshToken: refreshToken}, nil
}

func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	claims, err := middleware.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid: true,
		User: &pb.User{
			Id:       claims.UserID,
			Username: claims.Username,
			Email:    claims.Email,
		},
	}, nil
}
