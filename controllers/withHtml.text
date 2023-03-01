package controllers

//todo handle error if user doesn't exist
import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io/ioutil"
	"log"
	"login-project/models"
	"login-project/tools"
	"net/http"
	"strings"
)

func Login(writer http.ResponseWriter, request *http.Request) {
	t, _ := template.ParseFiles("views/login.html")
	t.Execute(writer, nil)

}

func Register(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("views/register.html")
	t.Execute(w, nil)

}
func Block(w http.ResponseWriter, r *http.Request) {
	pathVar := mux.Vars(r)
	email := pathVar["email"]
	user := models.Find(email)
	var block []byte
	var BlockHash string
	if user.HasBlock { // if user has block
		hash := user.LastHash
		BlockHash, block = tools.CreateBlock(email, false, hash)
	} else { // if user doesn't have block
		user.HasBlock = true
		BlockHash, block = tools.CreateBlock(email, true, "")
	}
	user.LastHash = BlockHash
	models.UpdateBlockStatus(user)
	w.Write(block)
	// saving the last block's sha256 code to user database.
}

func DecodeHash(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	fmt.Println(hash)
	blockData := models.FindBlockData(hash)
	fmt.Println("In decode hash : ", blockData.TransactionData)
	result, err := tools.Decrypt(blockData.TransactionData)
	if err != nil {
		fmt.Println("in decodeHash")
		log.Fatal(err.Error())
	}
	w.Write(result)
}

func Search(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("views/search.html")
	t.Execute(w, nil)
}

func ShowBlocks(w http.ResponseWriter, r *http.Request) {
	pathVar := mux.Vars(r)
	email := pathVar["email"]
	query := models.FindBlock(email)
	data, err := json.Marshal(query)
	if err != nil {
		fmt.Println("Error in Show Block : ", err.Error())
	}
	w.Write(data)
}

func UpdateInfo(w http.ResponseWriter, r *http.Request) {
	password, _ := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), 14)

	user := models.User{
		Email:     r.FormValue("email"),
		FirstName: r.FormValue("fname"),
		LastName:  r.FormValue("lname"),
		Password:  password,
	}
	models.Update(&user)
	t, _ := template.ParseFiles("views/index.html")
	t.Execute(w, nil)
	//w.Write([]byte("Success"))
}

func Update(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("JWT")
	if err != nil {
		fmt.Println(err.Error())
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenString := cookie.Value
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return tools.MySigningKey, nil
	})
	if err != nil {
		fmt.Println("hiiii : ", err.Error())
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		fmt.Println("hiiii 2")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := models.Find(claims.Issuer)
	t, _ := template.ParseFiles("views/update.html")
	t.Execute(w, user)

}

func Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("middleware", r.URL)
		fmt.Println("HI")
		h.ServeHTTP(w, r)
	})
}

func Index(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("views/index.html")
	t.Execute(w, "")

}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Content-Type", "application/html")
	r.ParseMultipartForm(10 << 20)
	password, _ := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), 14)
	userData := models.User{
		FirstName: strings.TrimSpace(r.FormValue("Fname")),
		LastName:  strings.TrimSpace(r.FormValue("Lname")),
		Email:     strings.TrimSpace(r.FormValue("email")),
		Gender:    r.FormValue("gender"),
		Password:  password,
		HasBlock:  false,
	}
	//reading image
	file, _, err := r.FormFile("image")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}
	defer file.Close()
	fileName := "profile_" + userData.FirstName + "*.jpg"
	tempFile, err := ioutil.TempFile("./picture", fileName)
	if err != nil {
		fmt.Println(err)
	}
	defer tempFile.Close()

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}
	str := strings.Replace(tempFile.Name(), "\\", "/", 1)
	userData.Path = str
	tempFile.Write(fileBytes)
	userData.Insert()
	t, err := template.ParseFiles("views/login.html")
	t.Execute(w, nil)

}

func Authenticate(writer http.ResponseWriter, request *http.Request) {
	Email := strings.TrimSpace(request.FormValue("email"))
	password := strings.TrimSpace(request.FormValue("password"))
	result := models.Find(Email)
	if result == nil {
		writer.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(writer, "No User exists")
		return
	}
	err := bcrypt.CompareHashAndPassword(result.Password, []byte(password))
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "bad request")
		return
	}
	token := tools.CreatJWT(result)
	cookie := http.Cookie{
		Name:     "JWT",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,

		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(writer, &cookie)
	t, err := template.ParseFiles("views/welcome.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	result.JWT = token
	models.InsertToken(result)
	fmt.Println("In  Authe")
	t.Execute(writer, result)
}

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
	t, _ := template.ParseFiles("views/index.html")
	t.Execute(writer, nil)
}

//
