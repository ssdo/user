package user_test

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/ssdo/user"
	"github.com/ssgo/log"
	"testing"
)

var prevSecretForAuthTest string
var prevUserIdForAuthTest string

func TestAuthVerifyCode(t *testing.T) {
	user.SetPhoneEncryptOffset("3jCHe3rlu2896y8grYgdhw==")
	user.SetPhoneEncryptOffset("1kHhroMojvHpdCkCBE7WuA==")

	imageCode := ""
	verifyCode := ""
	serve := user.NewServe(user.Config{
		MessageSender: func(target string, bizName string, args []string) bool {
			if len(args) > 0 {
				verifyCode = args[0]
			}
			return true
		},
		CodeImageMaker: func(code string) []byte {
			imageCode = code
			imageData := user.DefaultCodeImageMaker(code)
			return imageData
		},
	})

	const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"

	if r, imageData := serve.SendImageCode(DeviceId, Ip, log.DefaultLogger); r != user.OK || imageData == nil {
		t.Fatal("SendImageCode not OK")
	}

	if serve.AuthImageCode(DeviceId, "badCode", log.DefaultLogger) == user.OK {
		t.Fatal("AuthVerifyCode not Failed")
	}

	if serve.AuthImageCode(DeviceId, imageCode, log.DefaultLogger) != user.OK {
		t.Fatal("AuthVerifyCode not OK")
	}

	if serve.SendVerifyCode(Phone, DeviceId, Ip, log.DefaultLogger) != user.OK {
		t.Fatal("SendVerifyCode not OK")
	}

	if ok, _, _ := serve.AuthVerifyCode(Phone, DeviceId, Ip, "badCode", log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthVerifyCode not Failed", ok)
	}

	if ok, userId, secret := serve.AuthVerifyCode(Phone, DeviceId, Ip, verifyCode, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthVerifyCode not OK", ok)
	} else {
		prevUserIdForAuthTest = userId
		prevSecretForAuthTest = secret
	}
}

func TestAuthSecret(t *testing.T) {
	//const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"

	serve := user.NewServe(user.Config{})

	if ok, _ := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, "bad secret", log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthSecret not Failed", ok)
	}

	prevSecret2 := prevSecretForAuthTest
	if ok, secret := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecretForAuthTest, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthSecret not OK", ok)
	} else {
		prevSecretForAuthTest = secret
	}

	if ok, _ := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecret2, log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthSecret not Failed", ok)
	}

	if ok, _ := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecretForAuthTest, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthSecret not OK", ok)
	}
}
