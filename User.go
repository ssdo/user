package user

import (
	"fmt"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

func (serve *Serve) Register(in interface{}, deviceId, ip string, logger *log.Logger) (result Result, newSecret string) {
	User := serve.config.TableUser

	// 验证手机号、IP、设备编号是否超出配额
	userInfo := map[string]interface{}{}
	u.Convert(in, &userInfo)
	fmt.Println(u.JsonP(userInfo), ".")
	phone := u.String(userInfo[User.Phone])
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, ""
	}

	if phone != "" {
		userInfo[User.Phone] = serve.EncryptPhone(phone)
	}

	// 验证通过后，查询 id
	db := serve.config.DB.CopyByLogger(logger)
	userId := ""
	// 分配一个userId并存储到数据库
	for i := 0; i < 10000; i++ {
		userId = serve.config.UserIdMaker()
		// 找到一个不重复的Id
		if db.Query(fmt.Sprint("SELECT `", User.Id, "` FROM `", User.Table, "` WHERE `", User.Id, "`=?"), userId).StringOnR1C1() == "" {
			break
		}
	}
	userInfo[User.Id] = userId

	password := u.String(userInfo[User.Password])
	if password != "" {
		salt := serve.config.SaltMaker()
		userInfo[User.Salt] = salt
		userInfo[User.Password] = serve.config.PasswordSigner(userId, password, salt, serve.salt)
	}

	if db.Insert(User.Table, userInfo).Error != nil {
		return StoreFailed, ""
	}
	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)

	return
}

func (serve *Serve) UpdateUser(userId string, in interface{}, logger *log.Logger) Result {
	if userId == "" {
		return StoreFailed
	}

	User := serve.config.TableUser

	// 验证手机号、IP、设备编号是否超出配额
	userInfo := map[string]interface{}{}
	u.Convert(in, &userInfo)
	phone := u.String(userInfo[User.Phone])
	delete(userInfo, User.Id)

	if phone != "" {
		userInfo[User.Phone] = serve.EncryptPhone(phone)
	}

	db := serve.config.DB.CopyByLogger(logger)
	password := u.String(userInfo[User.Password])
	if password != "" {
		salt := serve.config.SaltMaker()
		userInfo[User.Salt] = salt
		userInfo[User.Password] = serve.config.PasswordSigner(userId, password, salt, serve.salt)
	} else {
		delete(userInfo, User.Password)
		delete(userInfo, User.Salt)
	}

	if db.Update(User.Table, userInfo, "`"+User.Id+"`=?", userId).Error != nil {
		return StoreFailed
	}

	return OK
}

func (serve *Serve) EncryptPhone(phone string) string {
	return encryptPhone(phone, serve.phoneOffset)
}

func (serve *Serve) DecryptPhone(phone string) string {
	return decryptPhone(phone, serve.phoneOffset)
}
