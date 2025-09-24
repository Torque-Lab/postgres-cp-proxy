package control_plane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
)

var (
	// key be like username:dbname->db_url
	backendAddrTable = make(map[string]string)
	tableMutex       = &sync.RWMutex{}
	controlPlaneURL  = "http://localhost:8080/backend"
)
var auth_token = os.Getenv("AUTH_TOKEN")

func GetBackendAddress(key string) (string, error) {
	tableMutex.RLock()
	addr, ok := backendAddrTable[key]
	tableMutex.RUnlock()
	if ok {
		return addr, nil
	}
	resp, err := http.Get(controlPlaneURL + "?key=" + key)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Backend string `json:"backend"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	tableMutex.Lock()
	backendAddrTable[key] = result.Backend
	tableMutex.Unlock()
	return result.Backend, nil
}
func StartUpdateServer() {
	http.HandleFunc("/update-table", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Update request received")
		var req struct {
			AuthToken string `json:"auth_token"`
			OldKey    string `json:"old_key"`
			NewKey    string `json:"new_key"`
			Backend   string `json:"backend"`
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
		backendAddrTable[req.NewKey] = req.Backend
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
