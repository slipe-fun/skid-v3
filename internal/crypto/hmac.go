package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
)

func ComputeHMAC(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("hmac: key cannot be empty")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	defer func() {
		for i := range keyCopy {
			keyCopy[i] = 0
		}
		runtime.KeepAlive(keyCopy)
	}()

	var tag []byte
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("hmac panic: %v", r)
			}
		}()

		mac := hmac.New(sha256.New, keyCopy)
		mac.Write(data)
		tag = mac.Sum(nil)
	}()

	if err != nil {
		return nil, err
	}

	return tag, nil
}
