package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"example.com/mod/driver"
	"example.com/mod/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func init() {
	error := godotenv.Load()
	if error != nil {
		log.Fatalf("Error loading .env file: %v", error)
	}
}

func main() {
	db = driver.ConnectDB() // Call the correct function to connect to the database

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/signup", signup).Methods("POST")
	router.HandleFunc("/api/v1/login", login).Methods("POST")
	router.HandleFunc("/api/v1/logout", logout).Methods("POST")
	router.HandleFunc("/api/v1/protected", TokenVerifyMiddleware(ProtectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))

}

func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil

}

func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	json.NewDecoder(r.Body).Decode(&user)
	fmt.Println(user)

	if user.Email == "" || user.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.Error{Message: "Email and Password is required", Status: false, Data: nil})
		return
	}

	// Check if the user already exists
	var existingUserID int
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", user.Email).Scan(&existingUserID)
	if err == nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(models.Error{Message: "User with this email already exists", Status: false, Data: nil})
		return
	} else if err != sql.ErrNoRows {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.Error{Message: "Server Error", Status: false, Data: nil})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.Error{Message: "Error hashing password", Status: false, Data: nil})
		return
	}

	user.Password = string(hash)

	statement := "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id;"

	err = db.QueryRow(statement, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.Error{Message: "Server Error", Status: false, Data: nil})
		return
	}

	user.Password = ""
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.Success{Message: "User created successfully", Status: true, Data: user})
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" || user.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.Error{Message: "Email and Password is required", Status: false, Data: nil})
		return
	}

	password := user.Password
	row := db.QueryRow("select * from users where email=$1", user.Email)

	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(models.Error{Message: "The user does not exist", Status: false, Data: nil})
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.Error{Message: "Server Error", Status: false, Data: nil})
			return
		}
	}

	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(models.Error{Message: "Invalid Password", Status: false, Data: nil})
		return
	}

	token, err := GenerateToken(user)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.Error{Message: "Error generating token", Status: false, Data: nil})
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(models.Success{Message: "User Logged In Successfully", Status: true, Token: token, Data: user})

}

func logout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Logout")
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Protected")
}

// Path: middleware.go
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if bearerToken == nil || len(bearerToken) != 2 {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.Error{Message: "Invalid Token, Access Denied ", Status: false, Data: nil})
			return
		}

		tokenString := bearerToken[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			secret := os.Getenv("JWT_SECRET")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid, JWT Error Sigining Failed")
			}
			return []byte(secret), nil
		})

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.Error{Message: "UnAuthorised Token", Status: false, Data: nil})
			return
		}

		if token.Valid {
			next.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.Error{Message: "UnAuthorised Token", Status: false, Data: nil})
			return
		}

		next.ServeHTTP(w, r)
	})
}
