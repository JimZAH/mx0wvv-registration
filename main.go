package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const call_name_illegal = "![];#$%&'*+/=?^_`{|}~-±§:<>,"

type user struct {
	approved_by        int64
	blocked            bool
	blocked_by         int64
	callsign           string
	description        string
	extension_number   int
	first              string
	id                 uint64
	last               string
	registration_date  int64
	registration_email string
}

// Check data fields
func (u *user) Checks() error {

	// Check callsign
	if strings.ContainsAny(u.callsign, call_name_illegal) {
		return fmt.Errorf("callsign contains illegal characters")
	}

	// Check email address
	email := strings.Split(u.registration_email, "@")
	if len(email) == 1 {
		return fmt.Errorf("error email is not valid")
	}

	if email[1][len(email[1])-1] == 45 || email[1][0] == 45 {
		return fmt.Errorf("error email domain (-) at start or end")
	}

	if strings.ContainsAny(email[1], "!#$%&'*+/=?^_`{|}~") {
		return fmt.Errorf("error email domain contains illegal characters")
	}

	// Check first and last name
	if strings.ContainsAny(u.first, call_name_illegal) {
		return fmt.Errorf("error first name contains illegal characters")
	}
	if strings.ContainsAny(u.last, call_name_illegal) {
		return fmt.Errorf("error last name contains illegal characters")
	}

	return nil
}

// Generate id for user
func (u *user) GenerateId() error {

	ns := rand.NewSource(time.Now().UnixNano())
	u.id = rand.New(ns).Uint64()

	return nil
}

// Generate sip extension based on callsign
func (u *user) GenerateExtension() error {
	var gn []int

	for i, c := range strings.ToUpper(u.callsign) {
		gn = append(gn, int(c-48)+len(u.callsign)-i*i)
	}

	for i := 0; i < len(gn); i++ {
		u.extension_number = u.extension_number * 10
		u.extension_number = u.extension_number + gn[i]
	}

	return nil
}

func main() {
	New := user{
		0,
		true,
		1,
		"M1MIK",
		"New User",
		0,
		"Mike",
		0,
		"Hotel",
		time.Now().Unix(),
		"time123hotel@example.com"}

	err := New.Checks()
	if err != nil {
		fmt.Println(err)
	}

	err = New.GenerateExtension()
	if err != nil {
		fmt.Println(err)
	}

	err = New.GenerateId()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(New)

}
