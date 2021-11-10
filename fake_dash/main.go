package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	registeredNodes map[string]Node = make(map[string]Node)
	nodeCounter     int
	apiDefinitions  []APIDefinition
	apiDefsFileHash [20]byte
)

type Node struct {
	LastSeen time.Time
}

type NodeResponseOK struct {
	Status  string            `json:"status"`
	Message map[string]string `json:"message"`
	Nonce   string            `json:"nonce"`
}

type PolicyResponse struct {
	Status  string     `json:"status"`
	Message []DBPolicy `json:"message"`
	Nonce   string     `json:"nonce"`
}

type APIsResponseMessage struct {
	ApiDefinition *APIDefinition `bson:"api_definition" json:"api_definition"`
}

type APIsResponse struct {
	Message []APIsResponseMessage `json:"message"`
	Nonce   string                `json:"nonce"`
}

func handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	nodeId, nonce, found := getNodeAndNonceFromRequest(r)
	if !found {
		nodeCounter++
		registeredNodes[fmt.Sprint(nodeCounter)] = Node{
			LastSeen: time.Now(),
		}
		nodeId = fmt.Sprint(nodeCounter)
		nonce = nodeId
	}
	msg := make(map[string]string)
	msg["NodeID"] = nodeId
	resp := NodeResponseOK{
		Message: msg,
		Nonce:   nonce,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(respBytes); err != nil {
		log.Println(err)
		return
	}
	log.Println("Handled registerNode for node", nodeId, "with nonce", nonce)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	nodeId, nonce, found := getNodeAndNonceFromRequest(r)
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	node, registered := registeredNodes[nodeId]
	if !registered {
		log.Println("received ping from unregistered node", nodeId)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	node.LastSeen = time.Now()
	msg := make(map[string]string)
	msg["NodeID"] = nodeId
	resp := NodeResponseOK{
		Message: msg,
		Nonce:   nonce,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(respBytes); err != nil {
		log.Println(err)
		return
	}
	// log.Println("Handled ping for node", nodeId, "with nonce", nonce)
}

func handleDeRegister(w http.ResponseWriter, r *http.Request) {
	nodeId, _, found := getNodeAndNonceFromRequest(r)
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	delete(registeredNodes, nodeId)
	log.Println("Deregistered node", nodeId)
}

func handlePolicies(w http.ResponseWriter, r *http.Request) {
	resp := PolicyResponse{}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(respBytes)
	log.Println("Handled policy request", string(respBytes))
}

func handleAPIs(w http.ResponseWriter, r *http.Request) {
	apisResponseMessages := make([]APIsResponseMessage, len(apiDefinitions))
	for i := range apiDefinitions {
		apisResponseMessages[i] = APIsResponseMessage{
			ApiDefinition: &apiDefinitions[i],
		}
	}
	resp := APIsResponse{
		Message: apisResponseMessages,
		Nonce:   "",
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(respBytes)
	log.Println("Handled APIs request")
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s\n", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

func main() {
	// if err := loadAPIDefinitions(); err != nil {
	// 	panic(err)
	// }
	http.HandleFunc("/register/node", handleRegisterNode)
	http.HandleFunc("/register/ping", handlePing)
	http.HandleFunc("/system/node", handleDeRegister)
	http.HandleFunc("/system/policies", handlePolicies)
	http.HandleFunc("/system/apis", handleAPIs)
	http.HandleFunc("/", handleCatchAll)
	go updateAPIs()
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// Helper functions

func getNodeAndNonceFromRequest(r *http.Request) (string, string, bool) {
	nodeIds, nodeFound := r.Header[http.CanonicalHeaderKey("x-tyk-nodeid")]
	nonces, nonceFound := r.Header[http.CanonicalHeaderKey("x-tyk-nonce")]
	if nodeFound && nonceFound {
		return nodeIds[0], nonces[0], true
	}
	return "", "", false
}

func loadAPIDefinitions() error {
	apisFile, err := os.Open("apis.json")
	if err != nil {
		return err
	}
	defer apisFile.Close()
	apisBytes, err := ioutil.ReadAll(apisFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(apisBytes, &apiDefinitions); err != nil {
		return err
	}
	apiDefsFileHash = sha1.Sum(apisBytes)
	return nil
}

func updateNodes() {
	client := http.Client{}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s/tyk/reload/group", "localhost:8080"),
		nil,
	)
	if err != nil {
		panic(err)
	}
	req.Header.Set("x-tyk-authorization", "foo")
	resp, err := client.Do(req)
	if err != nil {
		log.Println("unsuccessful request to Tyk Gateway", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Println("unsuccessful response from Tyk Gateway on reload request")
		return
	}
}

func updateAPIs() {
	var lastHash [20]byte
	for {
		lastHash = apiDefsFileHash
		loadAPIDefinitions()
		if apiDefsFileHash != lastHash {
			log.Println("loaded", len(apiDefinitions), "API(s) from apis.json")
			updateNodes()
		}
		time.Sleep(1 * time.Second)
	}
}
