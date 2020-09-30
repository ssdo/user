package user

import (
	"fmt"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

func AuthPassword(phone, deviceId, ip, password string, logger *log.Logger) (result Result, userId, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, "", ""
	}
	phoneX := EncryptPhone(phone, phoneEncryptOffset)

	// 查询 userId、password
	db := Config.DB.CopyByLogger(logger)
	User := Config.UserTable
	userInfo := db.Query(fmt.Sprint("SELECT `", User.Id, "`, `", User.Password, "`, `", User.Salt, "` FROM `", User.Table, "` WHERE `", User.Phone, "`=?"), phoneX).MapOnR1()
	userId = u.String(userInfo[User.Id])
	passwordSign := u.String(userInfo[User.Password])
	salt := u.String(userInfo[User.Salt])
	if userId == "" || passwordSign == "" || salt == "" {
		return AuthFailed, "", ""
	}

	// 验证
	if Config.PasswordSigner(userId, password, salt) != passwordSign {
		return AuthFailed, "", ""
	}

	// 产生新的 Salt、Secret
	result, newSecret = processNewSecret(userId, deviceId, db)
	return
}

func AuthPasswordByUserId(userId, deviceId, ip, password string, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := checkLimits("", deviceId, ip, logger); r != OK {
		return r, ""
	}

	// 查询 userId、password
	db := Config.DB.CopyByLogger(logger)
	User := Config.UserTable
	userInfo := db.Query(fmt.Sprint("SELECT `", User.Id, "`, `", User.Password, "`, `", User.Salt, "` FROM `", User.Table, "` WHERE `", User.Id, "`=?"), userId).MapOnR1()
	userId = u.String(userInfo[User.Id])
	passwordSign := u.String(userInfo[User.Password])
	salt := u.String(userInfo[User.Salt])
	if userId == "" || passwordSign == "" || salt == "" {
		fmt.Println("  111")
		return AuthFailed, ""
	}

	// 验证
	if Config.PasswordSigner(userId, password, salt) != passwordSign {
		fmt.Println("  222")
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	return processNewSecret(userId, deviceId, db)
}

func ResetPassword(phone, deviceId, ip, verifyCode, newPassword string, logger *log.Logger) (result Result, userId, newSecret string) {
	result, userId, newSecret = AuthVerifyCode(phone, deviceId, ip, verifyCode, logger)
	if result != OK {
		return result, "", ""
	}

	result = UpdatePassword(userId, newPassword, logger)

	// 返回新的 Salt、Secret
	return result, userId, newSecret
}

func ChangePassword(userId, deviceId, ip, oldPassword, newPassword string, logger *log.Logger) (result Result, newSecret string) {
	result, newSecret = AuthPasswordByUserId(userId, deviceId, ip, oldPassword, logger)
	if result != OK {
		return result, ""
	}
	result = UpdatePassword(userId, newPassword, logger)
	return
}

func UpdatePassword(userId, newPassword string, logger *log.Logger) Result{
	// 产生新的密码签名和Salt
	salt := Config.SaltMaker()
	newPasswordSign := Config.PasswordSigner(userId, newPassword, salt)

	// 更新数据库
	db := Config.DB.CopyByLogger(logger)
	User := Config.UserTable
	if db.Update(User.Table, map[string]string{
		User.Password: newPasswordSign,
		User.Salt:     salt,
	}, "`"+User.Id+"`=?", userId).Error != nil {
		return StoreFailed
	}

	return OK
}
