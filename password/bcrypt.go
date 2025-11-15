package password

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// VerifyBcrypt compares a bcrypt hash with a plaintext password.
func VerifyBcrypt(hash, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return err == nil, err
}

// IsBcryptHash detects common bcrypt PHC prefixes.
func IsBcryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}
