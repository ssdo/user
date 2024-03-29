package user_test

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/ssdo/user"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
	"testing"
)

var prevUserIdForPasswordTest string

func TestResetPassword(t *testing.T) {
	verifyCode := ""
	serve := user.NewServe(user.Config{
		MessageSender: func(target string, bizName string, args []string) bool {
			if len(args) > 0 {
				verifyCode = args[0]
			}
			return true
		},
	})

	const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"
	const Password = "123"

	if serve.SendVerifyCode(Phone, DeviceId, Ip, log.DefaultLogger) != user.OK {
		t.Fatal("SendVerifyCode not OK")
	}

	passwordX := u.Sha256String(Password)
	userInfo := struct {
		Id string
	}{}
	if ok, _ := serve.ResetPassword(Phone, DeviceId, Ip, verifyCode, passwordX, &userInfo, log.DefaultLogger); ok != user.OK {
		t.Fatal("ResetPassword not OK", ok)
	}else{
		prevUserIdForPasswordTest = userInfo.Id
	}
}

func TestChangePassword(t *testing.T) {
	serve := user.NewServe(user.Config{})

	//const Phone = "139"
	const DeviceId = "AA"
	const Ip = "127.0.0.1"
	const OldPassword = "123"
	const NewPassword = "456"

	oldPasswordX := u.Sha256String(OldPassword)
	newPasswordX := u.Sha256String(NewPassword)
	if ok, _ := serve.ChangePassword(prevUserIdForPasswordTest, DeviceId, Ip, oldPasswordX, newPasswordX, log.DefaultLogger); ok != user.OK {
		t.Fatal("ChangePassword not OK", ok)
	}
}
