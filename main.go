package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/akamensky/argparse"
	"github.com/fatih/color"
)

func main() {
	start := time.Now()

	parser := argparse.NewParser("gobbler", "password cracker")

	var wordlist *string = parser.String("w", "wordlist", &argparse.Options{Required: true, Help: "Path to password wordlist"})
	var password *string = parser.String("p", "password", &argparse.Options{Required: false, Help: "Password hash to crack"})
	var passwordFile *string = parser.String("P", "password-file", &argparse.Options{Required: false, Help: "File with list of passwords to crack"})
	var hashType *string = parser.String("H", "hash", &argparse.Options{Required: false, Help: "Hash type to crack (md5, sha1, sha256, sha512)"})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	// error handling
	// Check to make sure a password is provided
	if *password == "" && *passwordFile == "" {
		log.Fatal(errors.New("password must have a value"))
	}

	// Check to make sure od or password-finly one form of password provided
	if *password != "" && *passwordFile != "" {
		log.Fatal(errors.New("please provide only password or password-file"))
	}

	// Check password-file is legit
	if *passwordFile != "" {
		if _, err := os.Stat(*passwordFile); errors.Is(err, os.ErrNotExist) {
			log.Fatal(errors.New("passwordFile does not exist"))
		}
	}

	// Check wordlist exists
	if _, err := os.Stat(*wordlist); errors.Is(err, os.ErrNotExist) {
		log.Fatal(errors.New("wordlist does not exist"))
	}

	// Check hash provided is legit
	if *hashType != "md5" && *hashType != "sha256" && *hashType != "sha512" && *hashType != "sha1" {
		log.Fatal(errors.New("hash type is not valid"))
	}

	if *password != "" {
		found, err := crack_single(*password, *wordlist, *hashType)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Password: ")

		passwordGreen := color.New(color.FgGreen, color.Bold)
		hashGreen := color.New(color.FgGreen)

		fmt.Println(passwordGreen.Sprint(found) + " - " + hashGreen.Sprint(*password))

		duration := time.Since(start)
		fmt.Println("Found in ", duration)
	} else if *passwordFile != "" {
		passwordsToCrack, err := readLines(*passwordFile)
		if err != nil {
			log.Fatal(err)
		}

		passwords, err := crack_list(passwordsToCrack, *wordlist, *hashType)
		if err != nil {
			log.Fatal(err)
		}

		passwordGreen := color.New(color.FgGreen, color.Bold)
		hashGreen := color.New(color.FgGreen)

		fmt.Println("Passwords: ")
		for i, foundpassword := range passwords {
			fmt.Println(passwordGreen.Sprint(foundpassword) + " - " + hashGreen.Sprint(passwordsToCrack[i]))
		}

		duration := time.Since(start)
		fmt.Println("Found in ", duration)
	}
}

func crack_list(passwordsToCrack []string, wordlist string, hashtype string) ([]string, error) {
	passwords, err := readLines(wordlist)
	if err != nil {
		return []string{}, err
	}

	fmt.Println("Trying " + strconv.Itoa(len(passwords)) + " passwords")

	var foundPassword []string

	for _, passToCrack := range passwordsToCrack {
		switch hashtype {
		case "md5":
			var wg sync.WaitGroup
			wg.Add(len(passwords))

			for _, password := range passwords {
				go func(password string) {
					defer wg.Done()

					hash := md5.Sum([]byte(password))

					if hex.EncodeToString(hash[:]) == passToCrack {
						foundPassword = append(foundPassword, password)
					}
				}(password)
			}

			wg.Wait()
		case "sha1":
			var wg sync.WaitGroup
			wg.Add(len(passwords))

			for _, password := range passwords {
				go func(password string) {
					defer wg.Done()

					hash := sha1.Sum([]byte(password))

					if hex.EncodeToString(hash[:]) == passToCrack {
						foundPassword = append(foundPassword, password)
					}
				}(password)
			}

			wg.Wait()
		case "sha256":
			var wg sync.WaitGroup
			wg.Add(len(passwords))

			for _, password := range passwords {
				go func(password string) {
					defer wg.Done()

					hash := sha256.Sum256([]byte(password))

					if hex.EncodeToString(hash[:]) == passToCrack {
						foundPassword = append(foundPassword, password)
					}
				}(password)
			}

			wg.Wait()
		case "sha512":
			var wg sync.WaitGroup
			wg.Add(len(passwords))

			for _, password := range passwords {
				go func(password string) {
					defer wg.Done()

					hash := sha512.Sum512([]byte(password))

					if hex.EncodeToString(hash[:]) == passToCrack {
						foundPassword = append(foundPassword, password)
					}
				}(password)
			}

			wg.Wait()
		}
	}

	if len(foundPassword) == 0 {
		return []string{}, errors.New("no password found")
	}

	return foundPassword, nil
}

func crack_single(passwordToCrack string, wordlist string, hashtype string) (string, error) {
	// Get passwords from wordlist
	passwords, err := readLines(wordlist)
	if err != nil {
		return "", err
	}

	fmt.Println("Trying " + strconv.Itoa(len(passwords)) + " passwords")

	var foundPassword string

	switch hashtype {
	case "md5":
		var wg sync.WaitGroup
		wg.Add(len(passwords))

		for _, password := range passwords {
			go func(password string) {
				defer wg.Done()

				hash := md5.Sum([]byte(password))

				if hex.EncodeToString(hash[:]) == passwordToCrack {
					foundPassword = password
				}
			}(password)
		}

		wg.Wait()
	case "sha1":
		var wg sync.WaitGroup
		wg.Add(len(passwords))

		for _, password := range passwords {
			go func(password string) {
				defer wg.Done()

				hash := sha1.Sum([]byte(password))

				if hex.EncodeToString(hash[:]) == passwordToCrack {
					foundPassword = password
				}
			}(password)
		}

		wg.Wait()
	case "sha256":
		var wg sync.WaitGroup
		wg.Add(len(passwords))

		for _, password := range passwords {
			go func(password string) {
				defer wg.Done()

				hash := sha256.Sum256([]byte(password))

				if hex.EncodeToString(hash[:]) == passwordToCrack {
					foundPassword = password
				}
			}(password)
		}

		wg.Wait()
	case "sha512":
		var wg sync.WaitGroup
		wg.Add(len(passwords))

		for _, password := range passwords {
			go func(password string) {
				defer wg.Done()

				hash := sha512.Sum512([]byte(password))

				if hex.EncodeToString(hash[:]) == passwordToCrack {
					foundPassword = password
				}
			}(password)
		}

		wg.Wait()
	}

	if foundPassword == "" {
		return "", errors.New("no password found")
	}

	return foundPassword, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
