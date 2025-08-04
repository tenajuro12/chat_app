package database

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
)

var Client *mongo.Client
var DB *mongo.Database

func InitMongo() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}

	Client = client
	DB = client.Database("chat_auth")
	log.Println("Connected to MongoDB (Auth Service)")
}

func GetUsersCollection() *mongo.Collection {
	return DB.Collection("users")
}

func GetRefreshTokensCollection() *mongo.Collection {
	return DB.Collection("refresh_tokens")
}
