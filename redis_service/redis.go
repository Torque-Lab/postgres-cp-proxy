package redisservice

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisService struct {
	client *redis.Client
}

var instance *RedisService
var once sync.Once

// GetInstance returns the singleton RedisService instance
func GetInstance() *RedisService {
	once.Do(func() {
		instance = &RedisService{}
		instance.initClient()
	})
	return instance
}

func (r *RedisService) initClient() {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}

	r.client = redis.NewClient(opt)
	log.Println("Redis client initialized")

	go r.monitorConnection()
}

func (r *RedisService) monitorConnection() {
	ctx := context.Background()
	retries := 0

	for {
		_, err := r.client.Ping(ctx).Result()
		if err != nil {
			retries++
			if retries > 5 {
				log.Println("Max Redis reconnection attempts reached")
				return
			}
			wait := time.Duration(min(retries*200, 1000)) * time.Millisecond
			log.Printf("Redis reconnecting... attempt %d", retries)
			time.Sleep(wait)
			continue
		}
		if retries > 0 {
			log.Println("Redis client reconnected successfully")
		} else {
			log.Println("Redis client connected")
		}
		retries = 0
		time.Sleep(5 * time.Second)
	}
}

func (r *RedisService) Connect(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	log.Println("Connected to Redis")
	return nil
}

func (r *RedisService) Disconnect(ctx context.Context) error {
	if err := r.client.Close(); err != nil {
		return fmt.Errorf("error disconnecting from Redis: %w", err)
	}
	log.Println("Redis client disconnected")
	return nil
}

func (r *RedisService) GetClient(ctx context.Context) *redis.Client {
	if err := r.client.Ping(ctx).Err(); err != nil {
		log.Println("Redis client not connected, reconnecting...")
		_ = r.Connect(ctx)
	}
	return r.client
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
