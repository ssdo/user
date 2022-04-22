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
	phone := u.String(userInfo[User.Phone])
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, ""
	}

	if phone != "" {
		userInfo[User.Phone] = EncryptPhone(phone, phoneEncryptOffset)
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
		userInfo[User.Password] = serve.config.PasswordSigner(userId, password, salt)
	}

	if db.Insert(User.Table, userInfo).Error != nil {
		return StoreFailed, ""
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)
	return
}
