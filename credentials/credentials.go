// Package credentials provides password hashing and verification for the
// protosource-auth User aggregate. Hashes are produced with argon2id using
// the PHC string format ("$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>") and
// stored as bytes on the User.password_hash field.
//
// Raw passwords never enter the event log — Create and ChangePassword
// commands carry the already-hashed bytes. Use Hash in the hand-written
// login/signup path to produce the bytes before dispatching the command,
// and Verify during login to check a submitted password against the stored
// hash.
package credentials

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters for argon2id. These target the OWASP-recommended profile for
// interactive logins as of 2024: 64 MiB memory, 3 iterations, 2 lanes,
// 16-byte random salt, 32-byte derived key.
const (
	paramMemory  = 64 * 1024 // 64 MiB
	paramTime    = 3
	paramThreads = 2
	paramSaltLen = 16
	paramKeyLen  = 32
)

// ErrMismatch is returned by Verify when the submitted password does not
// match the stored hash. Constant-time comparison is used to avoid leaking
// timing information.
var ErrMismatch = errors.New("credentials: password mismatch")

// ErrMalformedHash is returned when the stored hash bytes do not parse as a
// valid argon2id PHC string.
var ErrMalformedHash = errors.New("credentials: malformed hash")

// Hash produces an argon2id hash of password as a PHC-format byte string
// suitable for storage on User.password_hash. A fresh random salt is drawn
// from crypto/rand on every call, so two identical passwords produce two
// distinct hashes.
func Hash(password string) ([]byte, error) {
	salt := make([]byte, paramSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("credentials: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, paramTime, paramMemory, paramThreads, paramKeyLen)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		paramMemory,
		paramTime,
		paramThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return []byte(encoded), nil
}

// Verify checks whether password matches the stored argon2id hash.
// Returns nil on match, ErrMismatch on a legitimate mismatch, or
// ErrMalformedHash (wrapped) if the stored hash cannot be parsed.
//
// Verify re-derives the key using the salt and parameters encoded in the
// stored hash — this means Verify continues to work even if the package-
// level parameters are tightened later.
func Verify(hash []byte, password string) error {
	salt, key, memory, time, threads, err := parse(hash)
	if err != nil {
		return err
	}
	candidate := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(key)))
	if subtle.ConstantTimeCompare(candidate, key) != 1 {
		return ErrMismatch
	}
	return nil
}

// parse decodes a PHC-format argon2id hash into its component parts.
func parse(hash []byte) (salt, key []byte, memory, time uint32, threads uint8, err error) {
	parts := strings.Split(string(hash), "$")
	// Expected layout: "", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"
	if len(parts) != 6 {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: expected 6 segments, got %d", ErrMalformedHash, len(parts))
	}
	if parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: unsupported algorithm %q", ErrMalformedHash, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid version: %v", ErrMalformedHash, err)
	}
	if version != argon2.Version {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: incompatible version %d (want %d)", ErrMalformedHash, version, argon2.Version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid parameters: %v", ErrMalformedHash, err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid salt: %v", ErrMalformedHash, err)
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid key: %v", ErrMalformedHash, err)
	}
	return salt, key, memory, time, threads, nil
}
