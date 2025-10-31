package env_config

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	fmt.Println("called init")
	if err != nil {
		log.Println("Warning: .env file not loaded, using system env")
	}
}
