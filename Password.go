package user

import (
	"fmt"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

func (serve *Serve)AuthPassword(phone, deviceId, ip, password string, logger *log.Logger) (result Result, userId, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, "", ""
	}
	phoneX := EncryptPhone(phone, phoneEncryptOffset)

	// 查询 userId、password
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	userInfo := db.Query(fmt.Sprint("SELECT `", User.Id, "`, `", User.Password, "`, `", User.Salt, "` FROM `", User.Table, "` WHERE `", User.Phone, "`=?"), phoneX).MapOnR1()
	userId = u.String(userInfo[User.Id])
	passwordSign := u.String(userInfo[User.Password])
	salt := u.String(userInfo[User.Salt])
	if userId == "" || passwordSign == "" || salt == "" {
		return AuthFailed, "", ""
	}

	// 验证
	if serve.config.PasswordSigner(userId, password, salt) != passwordSign {
		return AuthFailed, "", ""
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)
	return
}

func (serve *Serve)AuthPasswordByUserId(userId, deviceId, ip, password string, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits("", deviceId, ip, logger); r != OK {
		return r, ""
	}

	// 查询 userId、password
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	userInfo := db.Query(fmt.Sprint("SELECT `", User.Id, "`, `", User.Password, "`, `", User.Salt, "` FROM `", User.Table, "` WHERE `", User.Id, "`=?"), userId).MapOnR1()
	userId = u.String(userInfo[User.Id])
	passwordSign := u.String(userInfo[User.Password])
	salt := u.String(userInfo[User.Salt])
	if userId == "" || passwordSign == "" || salt == "" {
		fmt.Println("  111")
		return AuthFailed, ""
	}

	// 验证
	if serve.config.PasswordSigner(userId, password, salt) != passwordSign {
		fmt.Println("  222")
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	return serve.processNewSecret(userId, deviceId, db)
}

func (serve *Serve)ResetPassword(phone, deviceId, ip, verifyCode, newPassword string, logger *log.Logger) (result Result, userId, newSecret string) {
	result, userId, newSecret = serve.AuthVerifyCode(phone, deviceId, ip, verifyCode, logger)
	if result != OK {
		return result, "", ""
	}

	result = serve.UpdatePassword(userId, newPassword, logger)

	// 返回新的 Salt、Secret
	return result, userId, newSecret
}

func (serve *Serve)ChangePassword(userId, deviceId, ip, oldPassword, newPassword string, logger *log.Logger) (result Result, newSecret string) {
	result, newSecret = serve.AuthPasswordByUserId(userId, deviceId, ip, oldPassword, logger)
	if result != OK {
		return result, ""
	}
	result = serve.UpdatePassword(userId, newPassword, logger)
	return
}

func (serve *Serve)UpdatePassword(userId, newPassword string, logger *log.Logger) Result{
	// 产生新的密码签名和Salt
	salt := serve.config.SaltMaker()
	newPasswordSign := serve.config.PasswordSigner(userId, newPassword, salt)

	// 更新数据库
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	if db.Update(User.Table, map[string]string{
		User.Password: newPasswordSign,
		User.Salt:     salt,
	}, "`"+User.Id+"`=?", userId).Error != nil {
		return StoreFailed
	}

	return OK
}
