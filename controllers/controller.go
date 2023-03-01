package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"login-project/models"
	"login-project/tools"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func errorHandler(err error) {
	if err != nil {
		log.Println(err.Error())
	}
}

// RegisterUser user Registration
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	//fixme empty body can also be registered
	w.Header().Set("Content-Type", "application/json")

	var cred models.Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	defer r.Body.Close()
	errorHandler(err)
	log.Printf("%+v", cred)
	if cred.Email != "" && cred.Password != "" && cred.FirstName != "" {
		password, _ := bcrypt.GenerateFromPassword([]byte(cred.Password), 14)
		userData := models.User{
			FirstName: strings.TrimSpace(cred.FirstName),
			LastName:  strings.TrimSpace(cred.LastName),
			Email:     strings.TrimSpace(cred.Email),
			Gender:    cred.Gender,
			Password:  password,
			HasBlock:  false,
		}
		userData.Insert()
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Registered Successfully"))
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Not sufficient information"))
	}
}

// Authenticate User Login
func Authenticate(writer http.ResponseWriter, request *http.Request) {
	var cred models.Login
	if err := json.NewDecoder(request.Body).Decode(&cred); err != nil {
		log.Print(err)
	}
	if cred.Email != "" && cred.Password != "" {
		Email := strings.TrimSpace(cred.Email)
		password := strings.TrimSpace(cred.Password)
		result := models.Find(Email)
		if result == nil {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(writer, "No User exists")
			return
		}
		err := bcrypt.CompareHashAndPassword(result.Password, []byte(password))
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(writer, "bad request or wrong password")
			return
		}
		token := tools.CreatJWT(result)
		cookie := http.Cookie{
			Name:     "JWT",
			Value:    token,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: false,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		}
		http.SetCookie(writer, &cookie)

		if err != nil {
			fmt.Println(err.Error())
			return
		}
		result.JWT = token
		models.InsertToken(result)
		fmt.Println("Welcome user")
		return

	} else {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Not sufficient information"))
	}
	defer request.Body.Close()
}

// Logout User
func Logout(writer http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "JWT",
		Value:    "",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(writer, &cookie)

}

// Update user information
func Update(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookie, err := r.Cookie("JWT")
	if err != nil {
		fmt.Println(err.Error())
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenString := cookie.Value
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return tools.MySigningKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {

		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := models.Find(claims.Issuer)
	userJson, _ := json.Marshal(user)
	w.Write(userJson)
	w.WriteHeader(http.StatusFound)
	defer r.Body.Close()
}

func UpdateInfo(w http.ResponseWriter, r *http.Request) {
	var cred models.Credentials
	json.NewDecoder(r.Body).Decode(&cred)
	password, _ := bcrypt.GenerateFromPassword([]byte(cred.Password), 14)

	user := models.User{
		Email:     cred.Email,
		FirstName: cred.FirstName,
		LastName:  cred.LastName,
		Password:  password,
	}
	models.Update(&user)

	w.Write([]byte("Success"))
	w.WriteHeader(http.StatusOK)
	defer r.Body.Close()
}

// Block for creating a block /block/email_address
func Block(w http.ResponseWriter, r *http.Request) {
	var input models.BlockGen
	err := json.NewDecoder(r.Body).Decode(&input)
	errorHandler(err)
	//todo Sender data can be retrieved from token value.
	pathVar := mux.Vars(r)
	email := pathVar["email"]
	user := models.Find(email)
	var block []byte
	var BlockHash string
	if user.HasBlock { // if user has block
		hash := user.LastHash
		BlockHash, block = tools.CreateBlock(email, input, false, hash)
	} else { // if user doesn't have block
		user.HasBlock = true
		BlockHash, block = tools.CreateBlock(email, input, true, "")
	}
	// saving the last block's sha256 code to user database.
	user.LastHash = BlockHash
	models.UpdateBlockStatus(user)
	w.Write(block)
	defer r.Body.Close()

}

// DecodeHash for decoding hash
func DecodeHash(w http.ResponseWriter, r *http.Request) {
	var hash models.HashStruct
	err := json.NewDecoder(r.Body).Decode(&hash)
	errorHandler(err)
	fmt.Println(hash)
	blockData := models.FindBlockData(hash.Hash)
	fmt.Println("In decode hash : ", blockData.TransactionData)
	result, err := tools.Decrypt(blockData.TransactionData)
	if err != nil {
		fmt.Println("in decodeHash")
		log.Fatal(err.Error())
	}
	w.Write(result)
	defer r.Body.Close()
}

func ShowBlocks(w http.ResponseWriter, r *http.Request) {
	var model models.EmailStruct
	json.NewDecoder(r.Body).Decode(&model)
	query := models.FindBlock(model.Email)
	data, err := json.Marshal(query)
	if err != nil {
		fmt.Println("Error in Show Block : ", err.Error())
	}
	w.Write(data)
	defer r.Body.Close()
}

func Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("middleware", r.URL)
		fmt.Println("HI")
		h.ServeHTTP(w, r)
	})
}

//
