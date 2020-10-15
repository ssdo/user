package user

import (
	"fmt"
	ssdb "github.com/ssgo/db"
	"github.com/ssgo/log"
	"github.com/ssgo/u"
)

//func (serve *Serve)checkLimits(phone, userName, deviceId, ip string, logger *log.Logger) Result {
func (serve *Serve)checkLimits(phone, deviceId, ip string, logger *log.Logger) Result {
	if phone != "" && !serve.phoneLimiter.Check(phone, logger) {
		return PhoneLimited
	}
	//if userName != "" && !UserNameLimiter.Check(userName, logger) {
	//	return UserNameLimited
	//}
	if deviceId != "" && !serve.deviceLimiter.Check(deviceId, logger) {
		return DeviceLimited
	}
	if ip != "" && !serve.ipLimiter.Check(ip, logger) {
		return IpLimited
	}
	return OK
}

func (serve *Serve)SendImageCode(deviceId, ip string, logger *log.Logger) (result Result, imageData []byte) {
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

func (serve *Serve)AuthImageCode(deviceId, imageCode string, logger *log.Logger) Result {

	// 验证
	imageCodeKey := fmt.Sprint("_IMAGE_CODE_", deviceId, "_", imageCode)
	rd := serve.config.Redis.CopyByLogger(logger)
	if rd.GET(imageCodeKey).String() != deviceId+imageCode {
		return AuthFailed
	}
	rd.DEL(imageCodeKey)
	return OK
}

func (serve *Serve)SendVerifyCode(phone, deviceId, ip string, logger *log.Logger) Result {
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

	if !rd.SETEX(fmt.Sprint("_VERIFY_CODE_", deviceId, "_", EncryptPhone(phone, phoneEncryptOffset), "_", verifyCode), 120+1, deviceId+verifyCode) {
		return StoreFailed
	}

	return OK
}

func (serve *Serve)AuthVerifyCode(phone, deviceId, ip, verifyCode string, logger *log.Logger) (result Result, userId, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits(phone, deviceId, ip, logger); r != OK {
		return r, "", ""
	}
	phoneX := EncryptPhone(phone, phoneEncryptOffset)

	// 验证
	verifyCodeKey := fmt.Sprint("_VERIFY_CODE_", deviceId, "_", phoneX, "_", verifyCode)
	rd := serve.config.Redis.CopyByLogger(logger)
	if rd.GET(verifyCodeKey).String() != deviceId+verifyCode {
		// 验证失败
		return AuthFailed, "", ""
	}
	rd.DEL(verifyCodeKey)

	// 验证通过后，查询 userId
	db := serve.config.DB.CopyByLogger(logger)
	User := serve.config.TableUser
	userId = db.Query(fmt.Sprint("SELECT `", User.Id, "` FROM `", User.Table, "` WHERE `", User.Phone, "`=?"), phoneX).StringOnR1C1()
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
			return StoreFailed, "", ""
		}
	}

	// 产生新的 Salt、Secret
	result, newSecret = serve.processNewSecret(userId, deviceId, db)
	return
}

func (serve *Serve)AuthSecret(userId, deviceId, ip, secret string, logger *log.Logger) (result Result, newSecret string) {
	// 验证手机号、IP、设备编号是否超出配额
	if r := serve.checkLimits("", deviceId, ip, logger); r != OK {
		return r, ""
	}
	// 查询 userId
	db := serve.config.DB.CopyByLogger(logger)

	// 查询secret、salt
	UserDevice := serve.config.TableSecret
	r := db.Query(fmt.Sprint("SELECT `", UserDevice.Secret, "`, `", UserDevice.Salt, "` FROM `", UserDevice.Table, "` WHERE `", UserDevice.UserId, "`=? AND `", UserDevice.DeviceId, "`=?"), userId, deviceId).MapOnR1()
	oldSecretSign := u.String(r[UserDevice.Secret])
	oldSalt := u.String(r[UserDevice.Salt])
	if oldSecretSign == "" || oldSalt == "" {
		return AuthFailed, ""
	}

	// 验证
	if serve.config.SecretSigner(userId, secret, oldSalt) != oldSecretSign {
		return AuthFailed, ""
	}

	// 产生新的 Salt、Secret
	return serve.processNewSecret(userId, deviceId, db)
}

func (serve *Serve)processNewSecret(userId, deviceId string, db *ssdb.DB) (result Result, newSecret string) {
	// 产生新的 Salt、Secret
	newSecret = serve.config.SecretMaker(userId, serve.config.TokenMaker())
	secretSalt := serve.config.SaltMaker()
	secretSign := serve.config.SecretSigner(userId, newSecret, secretSalt)

	// 更新Secret数据
	if db.Replace(serve.config.TableSecret.Table, map[string]string{
		serve.config.TableSecret.UserId:   userId,
		serve.config.TableSecret.DeviceId: deviceId,
		serve.config.TableSecret.Secret:   secretSign,
		serve.config.TableSecret.Salt:     secretSalt,
	}).Error != nil {
		return StoreFailed, ""
	}
	return OK, newSecret
}
