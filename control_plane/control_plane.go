package control_plane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

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
	resp, err := http.Get(controlPlaneURL + "api/v1/infra/postgres/route-table" + "?key=" + key + "&auth_token=" + auth_token)
	if err != nil {
		fmt.Println(err, "get error")
		return "", err
	}
	defer resp.Body.Close()
	var req struct {
		Backend  string          `json:"backend_url"`
		UserCred SCRAMCredential `json:"user_cred"`
	}
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
func StartUpdateServer() {
	http.HandleFunc("/api/v1/infra/postgres/update-table", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Update request received")
		var req struct {
			Message   string          `json:"message"`
			Success   bool            `json:"success"`
			AuthToken string          `json:"auth_token"`
			OldKey    string          `json:"old_key"`
			NewKey    string          `json:"new_key"`
			Backend   string          `json:"backend_url"`
			UserCred  SCRAMCredential `json:"user_cred"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.AuthToken != auth_token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tableMutex.Lock()
		defer tableMutex.Unlock()

		if req.OldKey != "" {
			if _, exists := backendAddrTable[req.OldKey]; exists {
				delete(backendAddrTable, req.OldKey)
				fmt.Println("Deleted old key:", req.OldKey)
			}
		}
		backendAddrTable[req.NewKey] = nodeInstance{Backend: req.Backend, UserCred: req.UserCred}
		fmt.Println("Updated mapping:", req.NewKey, "->", req.Backend)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	go func() {
		fmt.Println("Update server listening on :9000")
		if err := http.ListenAndServe(":9000", nil); err != nil {
			fmt.Println("Update server error:", err)
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
