package main

import (
	"fmt"
	"testing"
)

func TestAddUser(t *testing.T) {
	users := Users{
		ID:         "1",
		Name:       "2",
		Password:   "3",
		Email:      "4",
		IsAdmin:    0,
		CreateTime: "",
		UpdateTime: "",
		PublicKey:  "",
		SecretKey:  "",
	}
	AddUserKey(&users)
	fmt.Printf("%v", users)
}
