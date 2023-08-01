package user

import (
	"fmt"
	ssdb "github.com/ssgo/db"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

//func (serve *Serve)checkLimits(phone, userName, deviceId, ip string, logger *log.Logger) Result {
func (serve *Serve) checkLimits(phone, deviceId, ip string, logger *log.Logger) Result {
	if phone != "" && serve.phoneLimiter != nil && !serve.phoneLimiter.Check(phone, logger) {
		return PhoneLimited
	}
	//if userName != "" && !UserNameLimiter.Check(userName, logger) {
	//	return UserNameLimited
	//}
	if deviceId != "" && serve.deviceLimiter != nil && !serve.deviceLimiter.Check(deviceId, logger) {
		return DeviceLimited
	}
	if ip != "" && serve.ipLimiter != nil && !serve.ipLimiter.Check(ip, logger) {
		return IpLimited
	}
	return OK
}

func (serve *Serve) GetImageCode(deviceId, ip string, logger *log.Logger) (result Result, imageData []byte) {
	// 验证IP、设备编号是否超出配额
	if r := serve.checkLimits("", deviceId, ip, logger); r != OK {
		return r, nil
	}

	// 产生并缓存验证码
	rd := serve.config.Redis.CopyByLogger(logger)
	imageCode := serve.config.ImageCodeMaker()
	imageData = serve.config.CodeImageMaker(imageCode)
	if !rd.SETEX(fmt.Sprint("_IMAGE_CODE_", deviceId, "_", imageCode), serve.config.VerifyCodeExpiresMinutes*60+1, deviceId+imageCode) {
		return StoreFailed, nil
	}

	if imageData == nil {
		return MakeFailed, nil
	}
	return OK, imageData
}

func (serve *Serve) AuthImageCode(deviceId, imageCode string, logger *log.Logger) Result {

	// 验证
	imageCodeKey := fmt.Sprint("_IMAGE_CODE_", deviceId, "_", imageCode)
	rd := serve.config.Redis.CopyByLogger(logger)
	if rd.GET(imageCodeKey).String() != deviceId+imageCode {
		return AuthFailed
	}
	rd.DEL(imageCodeKey)
	return OK
}

func (serve *Serve) SendVerifyCode(phone, deviceId, ip string, logger *log.Logger) Result {
	if serve.config.MessageSender == nil {
		logger.Warning("no MessageSender")
		return SendFailed
	}

	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r
	}

	// 产生并缓存验证码
	rd := serve.config.Redis.CopyByLogger(logger)
	verifyCode := serve.config.VerifyCodeMaker()

	ok := serve.config.MessageSender(phone, "sendVerifyCode", []string{verifyCode, u.String(serve.config.VerifyCodeExpiresMinutes)})
	if !ok {
		return SendFailed
	}

	if !rd.SETEX(fmt.Sprint("_VERIFY_CODE_", deviceId, "_", serve.EncryptPhone(phone), "_", verifyCode), 120+1, deviceId+verifyCode) {
		return StoreFailed
	}

	return OK
}

func (serve *Serve) AuthVerifyCode(phone, deviceId, ip, verifyCode string, out interface{}, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, ""
	}
	phoneX := serve.EncryptPhone(phone)

	// 验证
	verifyCodeKey := fmt.Sprint("_VERIFY_CODE_", deviceId, "_", phoneX, "_", verifyCode)
	rd := serve.config.Redis.CopyByLogger(logger)
	if rd.GET(verifyCodeKey).String() != deviceId+verifyCode {
		// 验证失败
		return AuthFailed, ""
	}
	rd.DEL(verifyCodeKey)

	// 验证通过后，查询 id
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	//userId = db.Query(fmt.Sprint("SELECT `", User.Id, "` FROM `", User.Table, "` WHERE `", User.Phone, "`=? AND `", User.IsValid, "`=?"), phoneX, User.IsValidValue).StringOnR1C1()
	userInfo := db.Query(fmt.Sprint("SELECT * FROM `", User.Table, "` WHERE `", User.Phone, "`=?", User.isValidSql), phoneX).MapOnR1()
	delete(userInfo, User.Password)
	delete(userInfo, User.Salt)
	userId := u.String(userInfo[User.Id])
	if userId == "" {
		// 分配一个userId并存储到数据库
		for i := 0; i < 10000; i++ {
			userId = serve.config.UserIdMaker()
			// 找到一个不重复的Id
			if db.Query(fmt.Sprint("SELECT `", User.Id, "` FROM `", User.Table, "` WHERE `", User.Id, "`=?"), userId).StringOnR1C1() == "" {
				break
			}
		}
		if db.Insert(User.Table, map[string]string{
			User.Id:    userId,
			User.Phone: phoneX,
		}).Error != nil {
			return StoreFailed, ""
		}
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)
	if out != nil {
		u.Convert(userInfo, out)
	}
	return
}

func (serve *Serve) AuthSecret(userId, deviceId, ip, secret string, out interface{}, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits("", deviceId, ip, logger); r != OK {
		return r, ""
	}
	// 查询 id
	db := serve.config.DB.CopyByLogger(logger)

	// 查询secret、salt
	Device := serve.config.TableDevice
	secret2Sql := ""
	if Device.Secret2 != "" {
		secret2Sql = ", `" + Device.Secret2 + "`, `" + Device.Salt2 + "`"
	}
	r := db.Query(fmt.Sprint("SELECT `", Device.Secret, "`, `", Device.Salt, "`"+secret2Sql+" FROM `", Device.Table, "` WHERE `", Device.UserId, "`=? AND `", Device.DeviceId, "`=?"), userId, deviceId).MapOnR1()
	oldSecretSign := u.String(r[Device.Secret])
	oldSalt := u.String(r[Device.Salt])
	if oldSecretSign == "" || oldSalt == "" {
		return AuthFailed, ""
	}

	// 验证
	//fmt.Println("auth1:", serve.config.SecretSigner(userId, secret, oldSalt), oldSecretSign, userId, secret, oldSalt)
	authOk := serve.config.SecretSigner(userId, secret, oldSalt, serve.salt) == oldSecretSign
	if !authOk && Device.Secret2 != "" {
		// 使用备份的secret再验证一次
		oldSecretSign = u.String(r[Device.Secret2])
		oldSalt = u.String(r[Device.Salt2])
		if oldSecretSign != "" && oldSalt != "" {
			//fmt.Println("auth2:", serve.config.SecretSigner(userId, secret, oldSalt), oldSecretSign, userId, secret, oldSalt)
			authOk = serve.config.SecretSigner(userId, secret, oldSalt, serve.salt) == oldSecretSign
		}
	}
	if !authOk {
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)

	if result == OK {
		User := serve.config.TableUser
		userInfo := db.Query(fmt.Sprint("SELECT * FROM `", User.Table, "` WHERE `", User.Id, "`=?", User.isValidSql), userId).MapOnR1()
		delete(userInfo, User.Password)
		delete(userInfo, User.Salt)
		if userInfo == nil {
			// 用户不存在或者已经被禁用
			return AuthFailed, ""
		}
		if out != nil {
			u.Convert(userInfo, out)
		}
	}

	return
}

func (serve *Serve) processNewSecret(userId, deviceId string, db *ssdb.DB) (result Result, newSecret string) {
	Device := serve.config.TableDevice

	// 产生新的 Salt、Secret
	newSecret = serve.config.SecretMaker(userId, serve.config.TokenMaker())
	secretSalt := serve.config.SaltMaker()
	secretSign := serve.config.SecretSigner(userId, newSecret, secretSalt, serve.salt)

	// 更新Secret数据
	data := map[string]string{
		Device.Secret:   secretSign,
		Device.Salt:     secretSalt,
	}

	// 备份一次secret
	r := db.Query("SELECT `"+Device.Secret+"`,`"+Device.Salt+"` FROM `"+Device.Table+"` WHERE `"+Device.UserId+"`=? AND `"+Device.DeviceId+"`=?", userId, deviceId).StringMapResults()
	if len(r) > 0 {
		if Device.Secret2 != "" {
			data[Device.Secret2] = r[0][Device.Secret]
			data[Device.Salt2] = r[0][Device.Salt]
		}
		if db.Update(Device.Table, data, "`"+Device.UserId+"`=? AND `"+Device.DeviceId+"`=?", userId, deviceId).Error != nil {
			return StoreFailed, ""
		}
	}else{
		data[Device.UserId] = userId
		data[Device.DeviceId] = deviceId
		if db.Insert(Device.Table, data).Error != nil {
			return StoreFailed, ""
		}
	}

	return OK, newSecret
}
