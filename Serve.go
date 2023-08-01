package user

import (
	"github.com/ssdo/utility"
	"github.com/ssgo/db"
	"github.com/ssgo/redis"
	"github.com/ssgo/u"
)

type Serve struct {
	config        *Config
	phoneLimiter  *utility.Limiter
	ipLimiter     *utility.Limiter
	deviceLimiter *utility.Limiter
	salt          string
	phoneOffset   uint64
}

func NewServe(config Config) *Serve {
	if config.Redis == nil {
		config.Redis = redis.GetRedis("user", nil)
	}

	if config.DB == nil {
		config.DB = db.GetDB("user", nil)
	}

	//if config.PhoneLimitDuration == 0 {
	//	config.PhoneLimitDuration = time.Minute
	//}
	//if config.PhoneLimitTimes == 0 {
	//	config.PhoneLimitTimes = 10
	//}
	//if config.UserNameLimitDuration == 0 {
	//	config.UserNameLimitDuration = time.Minute
	//}
	//if config.UserNameLimitTimes == 0 {
	//	config.UserNameLimitTimes = 100
	//}
	//if config.IpLimitDuration == 0 {
	//	config.IpLimitDuration = time.Minute
	//}
	//if config.IpLimitTimes == 0 {
	//	config.IpLimitTimes = 100
	//}
	//if config.DeviceLimitDuration == 0 {
	//	config.DeviceLimitDuration = time.Minute
	//}
	//if config.DeviceLimitTimes == 0 {
	//	config.DeviceLimitTimes = 100
	//}

	if config.ImageCodeExpiresMinutes == 0 {
		config.ImageCodeExpiresMinutes = 5
	}
	if config.VerifyCodeExpiresMinutes == 0 {
		config.VerifyCodeExpiresMinutes = 2
	}
	if config.ImageCodeMaker == nil {
		config.ImageCodeMaker = DefaultImageCodeMaker
	}
	if config.CodeImageMaker == nil {
		config.CodeImageMaker = DefaultCodeImageMaker
	}
	if config.VerifyCodeMaker == nil {
		config.VerifyCodeMaker = DefaultVerifyCodeMaker
	}
	if config.UserIdMaker == nil {
		config.UserIdMaker = u.Id8
	}
	if config.TokenMaker == nil {
		config.TokenMaker = DefaultTokenMaker
	}
	if config.SaltMaker == nil {
		config.SaltMaker = DefaultSaltMaker
	}
	if config.SecretMaker == nil {
		config.SecretMaker = DefaultSecretMaker
	}
	if config.SecretSigner == nil {
		config.SecretSigner = DefaultSigner
	}
	if config.PasswordSigner == nil {
		config.PasswordSigner = DefaultSigner
	}

	if config.TableUser.Table == "" {
		config.TableUser.Table = "User"
	}
	if config.TableUser.Id == "" {
		config.TableUser.Id = "id"
	}
	if config.TableUser.Phone == "" {
		config.TableUser.Phone = "phone"
	}
	if config.TableUser.Password == "" {
		config.TableUser.Password = "password"
	}
	if config.TableUser.Salt == "" {
		config.TableUser.Salt = "salt"
	}
	if config.TableUser.IsValidField != "" {
		if config.TableUser.IsValidValue == "" {
			config.TableUser.IsValidValue = "1"
		}
		config.TableUser.isValidSql = " AND `" + config.TableUser.IsValidField + "`='" + config.TableUser.IsValidValue + "'"
	}

	if config.TableDevice.Table == "" {
		config.TableDevice.Table = "UserDevice"
	}
	if config.TableDevice.UserId == "" {
		config.TableDevice.UserId = "userId"
	}
	if config.TableDevice.DeviceId == "" {
		config.TableDevice.DeviceId = "deviceId"
	}
	if config.TableDevice.Secret == "" {
		config.TableDevice.Secret = "secret"
	}
	if config.TableDevice.Salt == "" {
		config.TableDevice.Salt = "salt"
	}
	//if config.TableDevice.Secret2 == "" {
	//	config.TableDevice.Secret2 = "secret2"
	//}
	//if config.TableDevice.Salt2 == "" {
	//	config.TableDevice.Salt2 = "salt2"
	//}

	serve := &Serve{config: &config}
	if config.PhoneLimitDuration != 0 && config.PhoneLimitTimes != 0 {
		serve.phoneLimiter = utility.NewLimiter("User_Phone", config.PhoneLimitDuration, config.PhoneLimitTimes, config.Redis)
	}
	if config.IpLimitDuration != 0 && config.IpLimitTimes != 0 {
		serve.ipLimiter = utility.NewLimiter("User_IP", config.IpLimitDuration, config.IpLimitTimes, config.Redis)
	}
	if config.DeviceLimitDuration != 0 && config.DeviceLimitTimes != 0 {
		serve.deviceLimiter = utility.NewLimiter("User_Device", config.DeviceLimitDuration, config.DeviceLimitTimes, config.Redis)
	}
	if config.PhoneOffset != "" {
		serve.phoneOffset = u.Uint64(u.DecryptAes(config.PhoneOffset, settedKey, settedIv))
		config.PhoneOffset = ""
	} else {
		serve.phoneOffset = 8767321298
	}

	serve.salt = config.GlobalSalt
	config.GlobalSalt = ""
	if serve.salt == "" {
		serve.salt = u.Base64([]byte{90, 221, 43, 54, 165, 65, 4, 8, 1, 3, 32, 41, 0, 1})
	}

	return serve
}
