package main

//todo make sure one email cant use multiple times
//todo upload images in local repository and save path in cloud
//fixme handle errors
import (
	"github.com/gorilla/mux"
	"log"
	"login-project/controllers"
	"net/http"
)

//var store = sessions.NewCookieStore(privateKey)

func main() {
	router := mux.NewRouter()

	router.Use(controllers.EnableCORS)
	router.HandleFunc("/api/login", controllers.Authenticate)
	router.HandleFunc("/api/register", controllers.RegisterUser)
	router.HandleFunc("/api/logout", controllers.Logout)
	router.HandleFunc("/api/update", controllers.Update)
	router.HandleFunc("/api/updateInfo", controllers.UpdateInfo).Methods("POST")

	router.HandleFunc("/api/block", controllers.Block)
	router.HandleFunc("/api/decode", controllers.DecodeHash)

	router.HandleFunc("/api/search/{email}", controllers.ShowBlocks)
	router.HandleFunc("/api/checkReceiver", controllers.CheckReceiver)
	//log.Fatal(http.ListenAndServe(":8080", handlers.CORS(
	//	handlers.AllowedOrigins([]string{"*"}),
	//	handlers.AllowCredentials(),
	//	handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
	//	handlers.AllowedHeaders([]string{"Origin, X-Request-With, Accept", "Authorization", "Content-Type"}),
	//)(router)))

	log.Fatal(http.ListenAndServe(":8080", router))

}
