package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"origins/agent/ebpf"
)

type IPRequest struct {
	IP string `json:"ip"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func main() {
	iface := flag.String("iface", "eth0", "Network interface to attach the XDP filter to")
	port := flag.String("port", "8080", "HTTP API port for control plane requests")
	flag.Parse()

	log.Printf("[ORIGINS AGENT] Starting eBPF filter on interface: %s", *iface)

	// Initialize eBPF manager
	mgr, err := ebpf.NewManager(*iface)
	if err != nil {
		log.Fatalf("[ERROR] Failed to initialize eBPF manager: %v", err)
	}
	defer mgr.Close()

	log.Printf("[ORIGINS AGENT] XDP program successfully loaded and attached to %s", *iface)

	// HTTP Handlers for Dashboard / API triggers
	http.HandleFunc("/api/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req IPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if err := mgr.BlockIP(req.IP); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Response{Status: "error", Message: err.Error()})
			return
		}

		log.Printf("[BLOCKED] IP added to hardware filter: %s", req.IP)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{Status: "success", Message: fmt.Sprintf("Blocked %s", req.IP)})
	})

	http.HandleFunc("/api/unblock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req IPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if err := mgr.UnblockIP(req.IP); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Response{Status: "error", Message: err.Error()})
			return
		}

		log.Printf("[UNBLOCKED] IP removed from filter: %s", req.IP)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{Status: "success", Message: fmt.Sprintf("Unblocked %s", req.IP)})
	})

	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{Status: "active"})
	})

	// Run HTTP server in background
	server := &http.Server{Addr: ":" + *port}
	go func() {
		log.Printf("[API] Control plane listening on :%s", *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ERROR] HTTP server failed: %v", err)
		}
	}()

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("\n[SHUTDOWN] Detaching XDP hook and exiting cleanly...")
}
