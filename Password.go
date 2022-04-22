package user

import (
	"fmt"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

func (serve *Serve) AuthPasswordByPhone(phone, deviceId, ip, password string, out interface{}, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, ""
	}
	phoneX := EncryptPhone(phone, phoneEncryptOffset)

	// 查询 id、password
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	userInfo := db.Query(fmt.Sprint("SELECT * FROM `", User.Table, "` WHERE `", User.Phone, "`=? AND `", User.IsValid, "`=?"), phoneX, User.IsValidValue).MapOnR1()
	userId := u.String(userInfo[User.Id])
	passwordSign := u.String(userInfo[User.Password])
	salt := u.String(userInfo[User.Salt])
	delete(userInfo, User.Password)
	delete(userInfo, User.Salt)
	if userId == "" || passwordSign == "" || salt == "" {
		return AuthFailed, ""
	}

	// 验证
	if serve.config.PasswordSigner(userId, password, salt) != passwordSign {
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)
	if out != nil {
		u.Convert(userInfo, out)
	}
	return
}

func (serve *Serve) AuthPasswordByUserId(userId, deviceId, ip, password string, out interface{}, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits("", deviceId, ip, logger); r != OK {
		return r, ""
	}

	// 查询 id、password
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	userInfo := db.Query(fmt.Sprint("SELECT * FROM `", User.Table, "` WHERE `", User.Id, "`=? AND `", User.IsValid, "`=?"), userId, User.IsValidValue).MapOnR1()
	userId = u.String(userInfo[User.Id])
	passwordSign := u.String(userInfo[User.Password])
	salt := u.String(userInfo[User.Salt])
	delete(userInfo, User.Password)
	delete(userInfo, User.Salt)

	if userId == "" || passwordSign == "" || salt == "" {
		return AuthFailed, ""
	}

	// 验证
	if serve.config.PasswordSigner(userId, password, salt) != passwordSign {
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)
	if out != nil {
		u.Convert(userInfo, out)
	}
	return
}

func (serve *Serve) ResetPassword(phone, deviceId, ip, verifyCode, newPassword string, out interface{}, logger *log.Logger) (result Result, newSecret string) {
	result, newSecret = serve.AuthVerifyCode(phone, deviceId, ip, verifyCode, out, logger)
	if result != OK {
		return result, ""
	}

	userInfo := map[string]string{}
	if out != nil {
		u.Convert(out, &userInfo)
	}
	result = serve.UpdatePassword(userInfo[serve.config.TableUser.Id], newPassword, logger)

	// 返回新的 Salt、Secret
	return result, newSecret
}

func (serve *Serve) ChangePassword(userId, deviceId, ip, oldPassword, newPassword string, logger *log.Logger) (result Result, newSecret string) {
	result, newSecret = serve.AuthPasswordByUserId(userId, deviceId, ip, oldPassword, nil, logger)
	if result != OK {
		return result, ""
	}
	result = serve.UpdatePassword(userId, newPassword, logger)
	return
}

func (serve *Serve) UpdatePassword(userId, newPassword string, logger *log.Logger) Result {
	// 产生新的密码签名和Salt
	salt := serve.config.SaltMaker()
	newPasswordSign := serve.config.PasswordSigner(userId, newPassword, salt)

	// 更新数据库
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	if db.Update(User.Table, map[string]string{
		User.Password: newPasswordSign,
		User.Salt:     salt,
	}, "`"+User.Id+"`=? AND `", User.IsValid, "`=?", userId, User.IsValidValue).Error != nil {
		return StoreFailed
	}

	return OK
}
