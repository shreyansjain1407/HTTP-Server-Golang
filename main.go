package main

import (
	"log"
	"net/http"
)

func main() {
	//Handlers for http server
	http.HandleFunc("/auth/", Auth)
	http.HandleFunc("/verify", Verify)
	http.HandleFunc("/README.txt/", Readme)
	http.HandleFunc("/stats", Stats)

	log.Fatal(http.ListenAndServe(":8080", nil))

}
