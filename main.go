package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	saltSize       = 16
	nonceSize      = 12
	keySize        = 32
	scryptN        = 32768
	scryptR        = 8
	scryptP        = 1
	vaultExtension = ".ccv"
)

// Vault represents the structure of the vault
type Vault struct {
	Name       string
	MasterHash string
	Salt       string
	Records    []Record
}

type Record struct {
	Name     string
	Username string
	Password string
}

var signedInVault *Vault
var derivedKey []byte

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Welcome to CC Password Manager")
	for {
		fmt.Println("What would you like to do?")
		fmt.Println("1. Create a new password vault")
		fmt.Println("2. Sign in to an existing password vault")
		if signedInVault != nil {
			fmt.Println("3. Add a password record to the vault")
			fmt.Println("4. Fetch a password record from the vault")
		}
		fmt.Println("Quit (enter q or quit)")

		scanner.Scan()
		input := scanner.Text()
		if input == "q" || input == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		switch input {
		case "1":
			createVault(scanner)
		case "2":
			signInToVault(scanner)
		case "3":
			if signedInVault != nil {
				addRecordToVault(scanner)
			} else {
				fmt.Println("Please sign in to a vault first.")
			}
		case "4":
			if signedInVault != nil {
				fetchRecordFromVault(scanner)
			} else {
				fmt.Println("Please sign in to a vault first.")
			}
		default:
			fmt.Println("Invalid option, please try again.")
		}
	}
}

func createVault(scanner *bufio.Scanner) {
	fmt.Println("Creating a new vault")
	fmt.Print("Please provide a name for the vault: ")
	scanner.Scan()
	vaultName := scanner.Text()
	if !isValidFilename(vaultName) {
		fmt.Println("Invalid vault name. Please try again.")
		return
	}

	fmt.Print("Please enter a master password: ")
	masterPassword, err := readPassword(scanner)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	fmt.Print("Please confirm the master password: ")
	confirmPassword, err := readPassword(scanner)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	if masterPassword != confirmPassword {
		fmt.Println("Passwords do not match. Please try again.")
		return
	}

	salt := generateSalt()
	hashedPassword, err := hashPassword(masterPassword + salt)
	if err != nil {
		fmt.Println("Failed to hash password:", err)
		return
	}

	vault := Vault{
		Name:       vaultName,
		MasterHash: hashedPassword,
		Salt:       salt,
		Records:    []Record{},
	}

	err = saveVault(vault)
	if err != nil {
		fmt.Println("Failed to save vault:", err)
		return
	}

	fmt.Printf("New vault created and saved as: %s%s\n", vaultName, vaultExtension)
}

func signInToVault(scanner *bufio.Scanner) {
	fmt.Print("Enter vault name: ")
	scanner.Scan()
	vaultName := scanner.Text()
	vaultFileName := fmt.Sprintf("%s%s", vaultName, vaultExtension)

	vault, err := loadVault(vaultFileName)
	if err != nil {
		fmt.Println("Failed to load vault:", err)
		return
	}

	fmt.Print("Enter password for the vault: ")
	masterPassword, err := readPassword(scanner)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	derivedKey, err = deriveKey(masterPassword, vault.Salt)
	if err != nil {
		fmt.Println("Failed to derive key:", err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(vault.MasterHash), []byte(masterPassword+vault.Salt))
	if err != nil {
		fmt.Println("Invalid master password. Please try again.")
		return
	}

	signedInVault = &vault
	fmt.Println("Thank you, you are now signed in.")
}

func addRecordToVault(scanner *bufio.Scanner) {
	fmt.Print("Please enter a name for the record: ")
	scanner.Scan()
	recordName := scanner.Text()

	fmt.Print("Please enter the username: ")
	scanner.Scan()
	username := scanner.Text()

	fmt.Print("Please enter the password: ")
	password, err := readPassword(scanner)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	encryptedPassword, err := encrypt(password, derivedKey)
	if err != nil {
		fmt.Println("Failed to encrypt password:", err)
		return
	}

	record := Record{
		Name:     recordName,
		Username: username,
		Password: fmt.Sprintf("%s", encryptedPassword),
	}

	signedInVault.Records = append(signedInVault.Records, record)

	err = saveVault(*signedInVault)
	if err != nil {
		fmt.Println("Failed to save vault:", err)
		return
	}

	fmt.Printf("Record added to vault: %s\n", signedInVault.Name)
}

func fetchRecordFromVault(scanner *bufio.Scanner) {
	fmt.Print("Please enter the name of the record: ")
	scanner.Scan()
	recordName := scanner.Text()

	for _, record := range signedInVault.Records {
		if record.Name == recordName {
			password, err := decrypt(record.Password, derivedKey)
			if err != nil {
				fmt.Println("Failed to decrypt password:", err)
				return
			}
			fmt.Printf("Record found: %s\n", record.Name)
			fmt.Printf("Username: %s\n", record.Username)
			fmt.Printf("Password: %s\n", password)
			return
		}
	}
	fmt.Println("Record not found.")
}

func isValidFilename(name string) bool {
	return !strings.ContainsAny(name, `/\?%*:|"<>`)
}

func readPassword(scanner *bufio.Scanner) (string, error) {
	fd := int(os.Stdin.Fd())
	var pass []byte
	var err error

	if term.IsTerminal(fd) {
		pass, err = term.ReadPassword(fd)
		fmt.Println()
	} else {
		scanner.Scan()
		pass = []byte(scanner.Text())
	}

	if err != nil {
		return "", err
	}

	return string(pass), nil
}

func generateSalt() string {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		fmt.Println("Failed to generate salt:", err)
		return ""
	}
	return hex.EncodeToString(salt)
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func deriveKey(password, salt string) ([]byte, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}
	key, err := scrypt.Key([]byte(password), saltBytes, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return key, nil
}

func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertextBase64 string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if len(encryptedBytes) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encryptedBytes[:nonceSize], encryptedBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plaintext), nil
}

func saveVault(vault Vault) error {
	fileName := fmt.Sprintf("%s%s", vault.Name, vaultExtension)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("Name: %s\nMasterHash: %s\nSalt: %s\n", vault.Name, vault.MasterHash, vault.Salt))
	if err != nil {
		return err
	}

	for _, record := range vault.Records {
		_, err = file.WriteString(fmt.Sprintf("Record: %s:%s:%s\n", record.Name, record.Username, record.Password))
		if err != nil {
			return err
		}
	}

	return nil
}

func loadVault(filename string) (Vault, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Vault{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	vault := Vault{}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name: ") {
			vault.Name = strings.TrimPrefix(line, "Name: ")
		} else if strings.HasPrefix(line, "MasterHash: ") {
			vault.MasterHash = strings.TrimPrefix(line, "MasterHash: ")
		} else if strings.HasPrefix(line, "Salt: ") {
			vault.Salt = strings.TrimPrefix(line, "Salt: ")
		} else if strings.HasPrefix(line, "Record: ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "Record: "), ":", 3)
			if len(parts) == 3 {
				record := Record{
					Name:     parts[0],
					Username: parts[1],
					Password: parts[2],
				}
				vault.Records = append(vault.Records, record)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return Vault{}, err
	}

	return vault, nil
}
