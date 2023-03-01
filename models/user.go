package models

import "time"

type User struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email" bson:"_id"`
	Gender    string `json:"gender"`
	Password  []byte `json:"password"`
	JWT       string
	HasBlock  bool   `json:"hasBlock" bson:"has_block"`
	LastHash  string `json:"genesisHash" bson:"genesis_hash"`
}
type Block struct {
	Sender          string
	Receiver        string
	Amount          int64
	TimeStamp       time.Time
	TransactionData string
	Hash            string
}
type BlockData struct {
	User            string `bson:"user"`
	Id              int    `json:"block_id" bson:"block_id"`
	Hash            string `json:"hash" bson:"hash"` // sha256
	TransactionData []byte `json:"transaction_data" bson:"transactionData"`
}

// for API
type Credentials struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email" bson:"_id"`
	Gender    string `json:"gender"`
	Password  string `json:"password"`
}
type Login struct {
	Email    string `json:"email" `
	Password string `json:"password"`
}
type HashStruct struct {
	Hash string `json:"hash"`
}
type EmailStruct struct {
	Email string `json:"email"`
}
type BlockGen struct {
	Receiver string `json:"receiver"`
	Amount   string `json:"amount"`
}

type CheckDifficulty struct {
	Sender    string
	Receiver  string
	Amount    int64
	TimeStamp time.Time
}

// todo email can be converted to bson _id to make it unique key
// todo there can be added role int which can control user access
