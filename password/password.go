package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params defines Argon2id parameters.
type Params struct {
	Time    uint32 // iterations
	Memory  uint32 // KiB
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

func DefaultParams() Params {
	return Params{Time: 1, Memory: 64 * 1024, Threads: 1, SaltLen: 16, KeyLen: 32}
}

// HashArgon2id returns a PHC-encoded string.
func HashArgon2id(password string) (string, error) {
	p := DefaultParams()
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return phcEncode(p, salt, dk), nil
}

// VerifyArgon2id checks a password against a PHC-encoded hash.
func VerifyArgon2id(encoded, password string) (bool, error) {
	p, salt, sum, err := phcDecode(encoded)
	if err != nil {
		return false, err
	}
	dk := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(sum)))
	if len(dk) != len(sum) {
		return false, nil
	}
	if subtle.ConstantTimeCompare(dk, sum) == 1 {
		return true, nil
	}
	return false, nil
}

// Validate applies the current password policy.
// Minimal policy: length >= 8 characters.
func Validate(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password_too_short")
	}
	return nil
}

func phcEncode(p Params, salt, sum []byte) string {
	// $argon2id$v=19$m=65536,t=1,p=1$<salt_b64>$<sum_b64>
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
}

func phcDecode(s string) (Params, []byte, []byte, error) {
	var p Params
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("bad_phc")
	}
	// parts[3] like m=65536,t=1,p=1
	var m, t, par uint32
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &par)
	if err != nil {
		return p, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, err
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, err
	}
	p = Params{Time: uint32(t), Memory: uint32(m), Threads: uint8(par), SaltLen: uint32(len(salt)), KeyLen: uint32(len(sum))}
	return p, salt, sum, nil
}
