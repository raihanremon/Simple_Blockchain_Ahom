package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"login-project/models"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	MySigningKey = []byte("AllYourBase")
	expireTime   = time.Now().Add(2 * time.Hour)
	key          = []byte("the-key-has-to-be-32-bytes-long!")
)

func CreatJWT(user *models.User) string {
	// Create the Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expireTime),
		Issuer:    user.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString(MySigningKey)
	return ss
}

func CreateBlock(sender string, info models.BlockGen, genesis bool, prevHash string) (string, []byte) {
	var wg sync.WaitGroup
	transactionPool := []string{}
	nonce := 6
	// block created with Json format
	blockData := &models.BlockData{}
	b := &models.Block{}
	cd := &models.CheckDifficulty{}
	b.New()
	blockData.User, b.Sender, cd.Sender = sender, sender, sender
	b.Receiver, cd.Receiver = info.Receiver, info.Receiver
	b.Amount, _ = strconv.ParseInt(info.Amount, 10, 64)
	cd.Amount = b.Amount
	cd.TimeStamp = time.Now()
	jsonData, _ := json.Marshal(cd)
	transHash := sha256.Sum256(jsonData)
	data := string(transHash[:])
	if genesis {
		blockData.Id = 0
		b.Hash = "00000"
	} else {
		serial := models.BlockNo(sender)
		blockData.Id = serial
		b.Hash = prevHash
	}
	block, err := json.Marshal(b)
	fmt.Println(block)
	if err != nil {
		fmt.Println("Error marshal : ", err.Error())
		return "nil", nil
	}

	diff := data[:nonce]
	result := simpleDifficulty(diff)
	ciphertext, err := encrypt(block)
	if result {
		fmt.Println("simple Transaction Added")
		blockData.TransactionData = ciphertext
		fmt.Println(string(ciphertext[:]))
		blockData.Hash = createHash(ciphertext)
		blockData.Insert()

	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			transactionPool = append(transactionPool, data)
			time.Sleep(time.Second * 5)
			fmt.Println("mid Transaction Added")
			blockData.TransactionData = ciphertext
			blockData.Hash = createHash(ciphertext)
			blockData.Insert()
		}()
	}
	wg.Wait()
	transactionPool = []string{}
	//Encryption Mechanism
	checker, _ := Decrypt(ciphertext)
	fmt.Println("Decrypted Cypher Text ", checker)
	if err != nil {
		log.Fatal(err)
	}
	return blockData.Hash, block
}

func encrypt(plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("in decrypt 1")
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println("in decrypt 2")
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func createHash(data []byte) string {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		fmt.Println(err.Error())
	}
	hash := h.Sum(nil)
	return fmt.Sprintf("%x", hash)
}

func simpleDifficulty(diff string) bool {
	count := 0
	for _, value := range diff {
		if (value >= 48 && value <= 57) || (value >= 97 && value <= 103) {
			count++
		} else {
			return false
		}
	}
	return true
}
