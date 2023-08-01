package user_test

import (
	"fmt"
	"github.com/ssdo/user"
	"testing"
)

func TestEncryptPhone(t *testing.T) {
	for _, phone := range []string{"139", "86-139-001", "+8613912345678", "021-1234567", "+86-021-1234567"} {
		phoneX := user.encryptPhone(phone, 8767321298)
		phoneD := user.decryptPhone(phoneX, 8767321298)
		fmt.Println("Phone", phone, phoneX, phoneD)
		if phoneD != phone {
			t.Error("failed on ", phone, phoneX, phoneD)
		}
	}
}
