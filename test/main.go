package main

import "fmt"

type human struct {
	Name string
	Age  int
}

func main() {
	Pranto := human{
		Name: "Pranto",
		Age:  25,
	}
	changeName(&Pranto)
	fmt.Printf("%+v \n", Pranto)
}

func changeName(person *human) {
	person.Name = "Dev"
}
