package control_plane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	redisservice "postgres-cp-proxy/redis_service"
	"sync"
)

type SCRAMCredential struct {
	Salt       string `json:"salt"` // base64 encoded
	Iterations int    `json:"iterations"`
	StoredKey  string `json:"stored_key"` // base64 encoded
	ServerKey  string `json:"server_key"` // base64 encoded
}

var (
	// key be like username:dbname->db_url
	backendAddrTable = make(map[string]nodeInstance)
	tableMutex       = &sync.RWMutex{}
)

type nodeInstance struct {
	Backend  string
	UserCred SCRAMCredential
}

var auth_token = os.Getenv("AUTH_TOKEN")
var controlPlaneURL = os.Getenv("CONTROL_PLANE_URL")

func GetBackendAddress(key string) (string, error) {
	var req struct {
		Backend  string          `json:"backend_url"`
		UserCred SCRAMCredential `json:"user_cred"`
	}
	ctx := context.Background()
	redisService := redisservice.GetInstance()

	client := redisService.GetClient(ctx)
	response, err := client.Get(ctx, key).Result()
	if err == nil {
		err = json.Unmarshal([]byte(response), &req)
		if err != nil {
			fmt.Println(err, "decode error")
			return "", err
		}
		tableMutex.Lock()
		backendAddrTable[key] = nodeInstance{Backend: req.Backend, UserCred: req.UserCred}
		tableMutex.Unlock()
		fmt.Println("Fetched backend for key:", key, "->", req.Backend)
		return req.Backend, nil
	}
	resp, err := http.Get(controlPlaneURL + "api/v1/infra/postgres/route-table" + "?key=" + key + "&auth_token=" + auth_token)
	if err != nil {
		fmt.Println(err, "get error")
		return "", err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		fmt.Println(err, "decode error")
		return "", err
	}
	tableMutex.Lock()
	backendAddrTable[key] = nodeInstance{Backend: req.Backend, UserCred: req.UserCred}
	tableMutex.Unlock()
	fmt.Println("Fetched backend for key:", key, "->", req.Backend)
	return req.Backend, nil
}
func StartSubscriber() {
	var req struct {
		Message   string          `json:"message"`
		Success   bool            `json:"success"`
		AuthToken string          `json:"auth_token"`
		OldKey    string          `json:"old_key"`
		NewKey    string          `json:"new_key"`
		Backend   string          `json:"backend_url"`
		UserCred  SCRAMCredential `json:"user_cred"`
	}

	ctx := context.Background()
	redisService := redisservice.GetInstance()
	client := redisService.GetClient(ctx)

	Subscriber := client.Subscribe(ctx, "update-table")
	go func() {
		for {
			msg, err := Subscriber.ReceiveMessage(ctx)
			if err != nil {
				fmt.Println("Error receiving message:", err)
				return
			}
			err = json.Unmarshal([]byte(msg.Payload), &req)
			if err != nil {
				fmt.Println("Error unmarshalling message:", err)
				return
			}
			if req.OldKey != "" {
				if _, exists := backendAddrTable[req.OldKey]; exists {
					delete(backendAddrTable, req.OldKey)
					fmt.Println("Deleted old key:", req.OldKey)
				}
			}
			if req.Success {
				tableMutex.Lock()
				backendAddrTable[req.NewKey] = nodeInstance{Backend: req.Backend, UserCred: req.UserCred}
				tableMutex.Unlock()
				fmt.Println("Updated mapping:", req.NewKey, "->", req.Backend)
			}
		}
	}()

}

func AddUserCredential(username_db_name string, backend string, cred SCRAMCredential) {
	tableMutex.Lock()
	defer tableMutex.Unlock()
	backendAddrTable[username_db_name] = nodeInstance{Backend: backend, UserCred: cred}
}

func GetUserCredential(username_db_name string) (SCRAMCredential, bool) {
	tableMutex.RLock()
	cred, exists := backendAddrTable[username_db_name]
	tableMutex.RUnlock()
	fmt.Println("lock released")
	if !exists {
		GetBackendAddress(username_db_name)
	}
	tableMutex.RLock()
	defer tableMutex.RUnlock()
	cred, exists = backendAddrTable[username_db_name]
	return cred.UserCred, exists
}
