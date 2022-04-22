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

	if r, imageData := serve.GetImageCode(DeviceId, Ip, log.DefaultLogger); r != user.OK || imageData == nil {
		t.Fatal("GetImageCode not OK")
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

	userInfo := struct {
		Id string
	}{}
	if ok, _ := serve.AuthVerifyCode(Phone, DeviceId, Ip, "badCode", &userInfo, log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthVerifyCode not Failed", ok)
	}

	if ok, secret := serve.AuthVerifyCode(Phone, DeviceId, Ip, verifyCode, &userInfo, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthVerifyCode not OK", ok)
	} else {
		prevUserIdForAuthTest = userInfo.Id
		prevSecretForAuthTest = secret
	}
}

func TestAuthSecret(t *testing.T) {
	//const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"

	serve := user.NewServe(user.Config{})
	userInfo := struct {
		Id string
	}{}

	if ok, _ := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, "bad secret", &userInfo, log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthSecret not Failed", ok)
	}

	prevSecret2 := prevSecretForAuthTest
	if ok, secret := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecretForAuthTest, &userInfo, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthSecret not OK", ok)
	} else {
		prevSecretForAuthTest = secret
	}

	if ok, _ := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecret2, &userInfo, log.DefaultLogger); ok == user.OK {
		t.Fatal("AuthSecret not Failed", ok)
	}

	if ok, _ := serve.AuthSecret(prevUserIdForAuthTest, DeviceId, Ip, prevSecretForAuthTest, &userInfo, log.DefaultLogger); ok != user.OK {
		t.Fatal("AuthSecret not OK", ok)
	}
}
