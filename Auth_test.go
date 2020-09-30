package user_test

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/ssege/user"
	"github.com/ssgo/log"
	"testing"
)

var prevSecretForAuthTest string
var prevUserIdForAuthTest string

func TestAuthVerifyCode(t *testing.T) {
	user.Init()
	user.SetPhoneEncryptOffset("3jCHe3rlu2896y8grYgdhw==")
	user.SetPhoneEncryptOffset("1kHhroMojvHpdCkCBE7WuA==")

	const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"

	if user.SendVerifyCode(Phone, DeviceId, Ip, log.DefaultLogger) == user.OK {
		t.Fatal("SendVerifyCode not Failed")
	}

	imageCode := ""
	user.Config.CodeImageMaker = func(code string) []byte {
		imageCode = code
		imageData := user.DefaultCodeImageMaker(code)
		//u.WriteFile("a.png", string(imageData))
		return imageData
	}
	if r, imageData := user.SendImageCode(DeviceId, Ip, log.DefaultLogger); r != user.OK || imageData == nil {
		t.Fatal("SendImageCode not OK")
	}

	if user.AuthImageCode(DeviceId, "badCode", log.DefaultLogger) == user.OK {
		t.Fatal("AuthVerifyCode not Failed")
	}

	if user.AuthImageCode(DeviceId, imageCode, log.DefaultLogger) != user.OK {
		t.Fatal("AuthVerifyCode not OK")
	}

	verifyCode := ""
	user.Config.MessageSender = func(target string, bizName string, args []string) bool {
		if len(args) > 0 {
			verifyCode = args[0]
		}
		return true
	}

	if user.SendVerifyCode(Phone, DeviceId, Ip, log.DefaultLogger) != user.OK {
		t.Fatal("SendVerifyCode not OK")
	}

	if ok, _, _ := user.AuthVerifyCode(Phone, DeviceId, Ip, "badCode", log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthVerifyCode not Failed", ok)
	}

	if ok, userId, secret := user.AuthVerifyCode(Phone, DeviceId, Ip, verifyCode, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthVerifyCode not OK", ok)
	} else {
		prevUserIdForAuthTest = userId
		prevSecretForAuthTest = secret
	}
}

func TestAuthSecret(t *testing.T) {
	const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"

	if ok, _ := user.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, "bad secret", log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthSecret not Failed", ok)
	}

	prevSecret2 := prevSecretForAuthTest
	if ok, secret := user.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecretForAuthTest, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthSecret not OK", ok)
	} else {
		prevSecretForAuthTest = secret
	}

	if ok, _ := user.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecret2, log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthSecret not Failed", ok)
	}

	if ok, _ := user.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecretForAuthTest, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthSecret not OK", ok)
	}
}
