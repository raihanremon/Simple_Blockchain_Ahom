package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"login-project/models"
	"login-project/tools"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v4"
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
			Balance:   "100",
		}
		userData.Insert()
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Registered Successfully"))

		// Creating block for registered user
		var input models.BlockGen
		var BlockHash string
		senderEmail := userData.Email
		input.Sender = senderEmail
		input.Receiver = ""
		input.Amount = "0"
		sender := models.Find(senderEmail)
		sender.HasBlock = true
		BlockHash, _ = tools.CreateBlock(senderEmail, input, true, "")
		sender.LastHash = BlockHash
		models.UpdateBlockStatus(sender)

		//admin := &models.Admin{}
		//user := &models.User{}
		//admin.Address = "0x13CC9936245c0BBbE89bfF1332D76f3991240C08"
		//sender.Balance = "100"
		//admin.Balance -= 100
		//models.UpdateBalance(user)
		//models.UpdateAdminBalance(admin)
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

	senderEmail := input.Sender
	receiverEmail := input.Receiver
	sender := models.Find(senderEmail)
	receiver := models.Find(receiverEmail)
	var block []byte
	var BlockHash string
	// if user has block
	hash := sender.LastHash
	senderBalance, err1 := strconv.ParseInt(sender.Balance, 10, 64)
	receiverBalance, err1 := strconv.ParseInt(receiver.Balance, 10, 64)
	amount, err2 := strconv.ParseInt(input.Amount, 10, 64)
	if err1 != nil || err2 != nil {
		log.Println(err1, err2)
	}
	senderBalance = senderBalance - amount
	receiverBalance = receiverBalance + amount
	sender.Balance = strconv.FormatInt(senderBalance, 10)
	receiver.Balance = strconv.FormatInt(receiverBalance, 10)
	models.UpdateBalance(sender)
	models.UpdateBalance(receiver)
	BlockHash, block = tools.CreateBlock(senderEmail, input, false, hash)

	// saving the last block's sha256 code to user database.
	sender.LastHash = BlockHash
	models.UpdateBlockStatus(sender)
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

func CheckReceiver(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	//var receiverEmail models.EmailStruct
	var receiverEmail map[string]string
	err := json.NewDecoder(r.Body).Decode(&receiverEmail)
	if err != nil {
		log.Println("Error in Check receiver : ", err.Error())
	}
	//fmt.Println(json.NewDecoder(r.Body).Decode(&receiverEmail))
	defer r.Body.Close()
	fmt.Println(receiverEmail)
	var exists bool
	var result string
	for _, v := range receiverEmail {
		result = v
	}
	fmt.Println(result)
	exists = models.CheckEmail(result)
	response := models.ReceiverExistsResponse{Exists: exists}
	json.NewEncoder(w).Encode(response)
}

func FetchHash(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Hashes sent")
	result := models.AllHash()
	data, _ := json.Marshal(&result)
	w.Write(data)
}

//func GetBalance(w http.ResponseWriter, r *http.Request){}

//
