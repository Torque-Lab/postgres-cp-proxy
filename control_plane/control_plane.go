package control_plane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"sync"
)

// --- User credential storage ---
type SCRAMCredential struct {
	Salt       string // base64 encoded
	Iterations int    // iterations count
	StoredKey  string // base64 encoded
	ServerKey  string // base64 encoded
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
	tableMutex.RLock()
	addr, ok := backendAddrTable[key]
	tableMutex.RUnlock()
	if ok {
		return addr.Backend, nil
	}
	resp, err := http.Get(controlPlaneURL + "api/v1/postgres/table" + "?key=" + key + "&auth_token=" + auth_token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var req struct {
		Backend  string          `json:"backend_url"`
		UserCred SCRAMCredential `json:"user_cred"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		return "", err
	}
	tableMutex.Lock()
	backendAddrTable[key] = nodeInstance{Backend: req.Backend, UserCred: req.UserCred}
	tableMutex.Unlock()
	return req.Backend, nil
}
func StartUpdateServer() {
	http.HandleFunc("/api/v1/postgres/update-table", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Update request received")
		var req struct {
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
	defer tableMutex.RUnlock()
	cred, exists := backendAddrTable[username_db_name]
	return cred.UserCred, exists
}
