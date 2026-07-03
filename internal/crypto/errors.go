package crypto

import "errors"

var ErrBadKeySize = errors.New("master key must be 32 bytes (AES-256)")
