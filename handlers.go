package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

//Map to store all the logs of when the users authenticate
var userLogAuth = make(map[string][]string)

//Map to store all the logs of when the users verify
var userLogVerify = make(map[string][]string)

//Map to store users and their tokens
var userMap = make(map[string]string)

//Auth handler
func Auth(w http.ResponseWriter, r *http.Request) {
	uname := strings.TrimPrefix(r.URL.Path, "/auth/")

	//Fetching the private key from file
	prvKey, err := ioutil.ReadFile("D:/JWT-Golang/key/id_rsa")
	if err != nil {
		log.Fatalln(err)
	}
	//Parsing the RSA Private Key
	signingKey, err := jwt.ParseRSAPrivateKeyFromPEM(prvKey)
	if err != nil {
		return
	}

	expirationTime := time.Now().Add(time.Hour * 24)
	claims := make(jwt.MapClaims)
	claims["sub"] = uname
	claims["exp"] = expirationTime.Unix()

	//This is the token that will be sent to the users
	tkn, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return
	}

	//Saving the details in a map and or updating them when necessary
	userMap[uname] = tkn

	//Storing the logs of users
	logs, ok := userLogAuth[uname]
	if ok {
		//update the UserLog map here
		logs = append(logs, time.Now().String())
		userLogAuth[uname] = logs
	} else {
		var nlogs []string
		nlogs = append(nlogs, time.Now().String())
		userLogAuth[uname] = nlogs
	}

	//Cookie formation. This is the cookie that will be sent to the user
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Path:    "/",
		Value:   tkn,
		Expires: expirationTime,
	})
}

//Verify Handler
func Verify(w http.ResponseWriter, r *http.Request) {
	//Fetchgin public key from flie
	iniPubKey, err := ioutil.ReadFile("D:/JWT-Golang/public.pem")
	if err != nil {
		log.Fatalln(err)
	}
	// Parsing public key
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(iniPubKey)
	if err != nil {
		return
	}

	//Fetching the received cookie
	cookie, err := r.Cookie("token")
	println("Exe1")
	if err != nil {
		if err == http.ErrNoCookie {
			println("No Cookie :(")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//This is the token string to be decoded, fetched from the value field of the cookie
	value := cookie.Value

	//Decoding the token fetched from the cookie
	token, _ := jwt.Parse(value, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return pubKey, nil
	})

	//If in case the token is invalid or unauthorized
	if token.Claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//This is the claims map that was set earlier while creation of the cookie
	claims := token.Claims.(jwt.MapClaims)
	var curUser = fmt.Sprintf("%s", claims["sub"])

	//Storing the logs of users
	_, ok := userMap[curUser]
	if ok {
		logs, ok := userLogVerify[curUser]
		if ok {
			logs = append(logs, time.Now().String())
			userLogVerify[curUser] = logs
		} else {
			var nlogs []string
			nlogs = append(nlogs, time.Now().String())
			userLogVerify[curUser] = nlogs
		}
		w.Write([]byte(fmt.Sprintf("%s", claims["sub"])))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

//Handler to output the README file to CLoudflare Engineering team
func Readme(w http.ResponseWriter, r *http.Request) {
	readme, _ := ioutil.ReadFile("Readme.txt")
	w.Write([]byte(string(readme)))
}

//Stats Handler
//Parsing the data from all maps and displaying it to the users
func Stats(w http.ResponseWriter, r *http.Request) {
	output := "STATISTICS \n"
	output += "Authorization logs of users: \n"
	for key, value := range userLogAuth {
		output += (key + " " + strings.Join(value, "\n") + "\n")
	}
	output += "Verification logs of users: \n"
	for key, value := range userLogVerify {
		output += (key + " " + strings.Join(value, "\n") + "\n")
	}
	w.Write([]byte(string(output)))
}
