package user

import (
	"github.com/ssdo/utility"
	"github.com/ssgo/db"
	"github.com/ssgo/log"
	"github.com/ssgo/redis"
	"github.com/ssgo/u"
	"time"
)

type Serve struct {
	config        *Config
	phoneLimiter  *utility.Limiter
	ipLimiter     *utility.Limiter
	deviceLimiter *utility.Limiter
}

func NewServe(config Config, logger *log.Logger) *Serve {
	if logger == nil {
		logger = log.DefaultLogger
	}

	if config.Redis == nil {
		config.Redis = redis.GetRedis("user", nil)
	}

	if config.DB == nil {
		config.DB = db.GetDB("user", nil)
	}

	if config.PhoneLimitDuration == 0 {
		config.PhoneLimitDuration = 5 * time.Minute
	}
	if config.PhoneLimitTimes == 0 {
		config.PhoneLimitTimes = 10000
	}
	if config.UserNameLimitDuration == 0 {
		config.UserNameLimitDuration = 5 * time.Minute
	}
	if config.UserNameLimitTimes == 0 {
		config.UserNameLimitTimes = 10000
	}
	if config.IpLimitDuration == 0 {
		config.IpLimitDuration = 5 * time.Minute
	}
	if config.IpLimitTimes == 0 {
		config.IpLimitTimes = 10000
	}
	if config.DeviceLimitDuration == 0 {
		config.DeviceLimitDuration = 5 * time.Minute
	}
	if config.DeviceLimitTimes == 0 {
		config.DeviceLimitTimes = 10000
	}
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

	//TableUser: TableUser{
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

	if config.TableSecret.Table == "" {
		config.TableSecret.Table = "UserDevice"
	}
	if config.TableSecret.UserId == "" {
		config.TableSecret.UserId = "userId"
	}
	if config.TableSecret.DeviceId == "" {
		config.TableSecret.DeviceId = "deviceId"
	}
	if config.TableSecret.Secret == "" {
		config.TableSecret.Secret = "secret"
	}
	if config.TableSecret.Salt == "" {
		config.TableSecret.Salt = "salt"
	}

	return &Serve{
		config:        &config,
		phoneLimiter:  utility.NewLimiter("Phone", config.PhoneLimitDuration, config.PhoneLimitTimes, config.Redis),
		ipLimiter:     utility.NewLimiter("IP", config.IpLimitDuration, config.IpLimitTimes, config.Redis),
		deviceLimiter: utility.NewLimiter("Device", config.DeviceLimitDuration, config.DeviceLimitTimes, config.Redis),
	}
}
