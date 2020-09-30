package user

import (
	"fmt"
	"github.com/ssgo/db"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

//func checkLimits(phone, userName, deviceId, ip string, logger *log.Logger) Result {
func checkLimits(phone, deviceId, ip string, logger *log.Logger) Result {
	if phone != "" && !PhoneLimiter.Check(phone, logger) {
		return PhoneLimited
	}
	//if userName != "" && !UserNameLimiter.Check(userName, logger) {
	//	return UserNameLimited
	//}
	if deviceId != "" && !DeviceLimiter.Check(deviceId, logger) {
		return DeviceLimited
	}
	if ip != "" && !IpLimiter.Check(ip, logger) {
		return IpLimited
	}
	return OK
}

func SendImageCode(deviceId, ip string, logger *log.Logger) (result Result, imageData []byte) {
	// 验证IP、设备编号是否超出配额
	if r := checkLimits("", deviceId, ip, logger); r != OK {
		return r, nil
	}

	// 产生并缓存验证码
	rd := Config.Redis.CopyByLogger(logger)
	imageCode := Config.ImageCodeMaker()
	imageData = Config.CodeImageMaker(imageCode)
	if !rd.SETEX(fmt.Sprint("_IMAGE_CODE_", deviceId, "_", imageCode), Config.VerifyCodeExpiresMinutes*60+1, deviceId+imageCode) {
		return StoreFailed, nil
	}

	if imageData == nil {
		return MakeFailed, nil
	}
	return OK, imageData
}

func AuthImageCode(deviceId, imageCode string, logger *log.Logger) Result {

	// 验证
	imageCodeKey := fmt.Sprint("_IMAGE_CODE_", deviceId, "_", imageCode)
	rd := Config.Redis.CopyByLogger(logger)
	if rd.GET(imageCodeKey).String() != deviceId+imageCode {
		return AuthFailed
	}
	rd.DEL(imageCodeKey)
	return OK
}

func SendVerifyCode(phone, deviceId, ip string, logger *log.Logger) Result {
	if Config.MessageSender == nil {
		logger.Warning("no MessageSender")
		return SendFailed
	}

	// 验证手机号、IP、设备编号是否超出配额
	if r := checkLimits(phone, deviceId, ip, logger); r != OK {
		return r
	}

	// 产生并缓存验证码
	rd := Config.Redis.CopyByLogger(logger)
	verifyCode := Config.VerifyCodeMaker()

	ok := Config.MessageSender(phone, "sendVerifyCode", []string{verifyCode, u.String(Config.VerifyCodeExpiresMinutes)})
	if !ok {
		return SendFailed
	}

	if !rd.SETEX(fmt.Sprint("_VERIFY_CODE_", deviceId, "_", EncryptPhone(phone, phoneEncryptOffset), "_", verifyCode), 120+1, deviceId+verifyCode) {
		return StoreFailed
	}

	return OK
}

func AuthVerifyCode(phone, deviceId, ip, verifyCode string, logger *log.Logger) (result Result, userId, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, "", ""
	}
	phoneX := EncryptPhone(phone, phoneEncryptOffset)

	// 验证
	verifyCodeKey := fmt.Sprint("_VERIFY_CODE_", deviceId, "_", phoneX, "_", verifyCode)
	rd := Config.Redis.CopyByLogger(logger)
	if rd.GET(verifyCodeKey).String() != deviceId+verifyCode {
		// 验证失败
		return AuthFailed, "", ""
	}
	rd.DEL(verifyCodeKey)

	// 验证通过后，查询 userId
	db := Config.DB.CopyByLogger(logger)
	User := Config.UserTable
	userId = db.Query(fmt.Sprint("SELECT `", User.Id, "` FROM `", User.Table, "` WHERE `", User.Phone, "`=?"), phoneX).StringOnR1C1()
	if userId == "" {
		// 分配一个userId并存储到数据库
		for i := 0; i < 10000; i++ {
			userId = Config.UserIdMaker()
			// 找到一个不重复的Id
			if db.Query(fmt.Sprint("SELECT `", User.Id, "` FROM `", User.Table, "` WHERE `", User.Id, "`=?"), userId).StringOnR1C1() == "" {
				break
			}
		}
		if db.Insert(User.Table, map[string]string{
			User.Id:    userId,
			User.Phone: phoneX,
		}).Error != nil {
			return StoreFailed, "", ""
		}
	}

	// 产生新的 Salt、Secret
	result, newSecret = processNewSecret(userId, deviceId, db)
	return
}

func AuthSecret(userId, deviceId, ip, secret string, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := checkLimits("", deviceId, ip, logger); r != OK {
		return r, ""
	}
	// 查询 userId
	db := Config.DB.CopyByLogger(logger)

	// 查询secret、salt
	UserDevice := Config.UserDeviceTable
	r := db.Query(fmt.Sprint("SELECT `", UserDevice.Secret, "`, `", UserDevice.Salt, "` FROM `", UserDevice.Table, "` WHERE `", UserDevice.UserId, "`=? AND `", UserDevice.DeviceId, "`=?"), userId, deviceId).MapOnR1()
	oldSecretSign := u.String(r[UserDevice.Secret])
	oldSalt := u.String(r[UserDevice.Salt])
	if oldSecretSign == "" || oldSalt == "" {
		return AuthFailed, ""
	}

	// 验证
	if Config.SecretSigner(userId, secret, oldSalt) != oldSecretSign {
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	return processNewSecret(userId, deviceId, db)
}

func processNewSecret(userId, deviceId string, db *db.DB) (result Result, newSecret string) {
	// 产生新的 Salt、Secret
	newSecret = Config.SecretMaker(userId, Config.TokenMaker())
	secretSalt := Config.SaltMaker()
	secretSign := Config.SecretSigner(userId, newSecret, secretSalt)

	// 更新Secret数据
	if db.Replace(Config.UserDeviceTable.Table, map[string]string{
		Config.UserDeviceTable.UserId:   userId,
		Config.UserDeviceTable.DeviceId: deviceId,
		Config.UserDeviceTable.Secret:   secretSign,
		Config.UserDeviceTable.Salt:     secretSalt,
	}).Error != nil {
		return StoreFailed, ""
	}
	return OK, newSecret
}
