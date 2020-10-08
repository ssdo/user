package user

import (
	"github.com/ssdo/utility"
	"github.com/ssgo/db"
	"github.com/ssgo/redis"
	"github.com/ssgo/u"
	"time"
)

var inited = false
var PhoneLimiter *utility.Limiter

//var UserNameLimiter *utility.Limiter
var IpLimiter *utility.Limiter
var DeviceLimiter *utility.Limiter

type Result uint8

const (
	OK Result = iota
	PhoneLimited
	//UserNameLimited
	DeviceLimited
	IpLimited
	StoreFailed
	MakeFailed
	SendFailed
	AuthFailed
)

// 用户表
type UserTable struct {
	Table string // 表名
	Id    string // id字段名
	//Name     string // 用户名字段名
	Phone    string // 手机号字段名
	Password string // 密码字段名
	Salt     string // 用于计算密码的salt字段名
}

// 用户设备关系表
type UserDeviceTable struct {
	Table    string // 表名
	UserId   string // 用户id字段名
	DeviceId string // 设备id字段名
	Secret   string // 密码字段名
	Salt     string // 用于计算密码的salt字段名
}

var Config = struct {
	Redis                    *redis.Redis                                            // Redis连接池
	DB                       *db.DB                                                  // 数据库连接池
	PhoneLimitDuration       time.Duration                                           // 手机号限制器时间间隔
	PhoneLimitTimes          int                                                     // 手机号限制器时间单位内允许的次数
	UserNameLimitDuration    time.Duration                                           // 用户名限制器时间间隔
	UserNameLimitTimes       int                                                     // 用户名限制器时间单位内允许的次数
	IpLimitDuration          time.Duration                                           // IP地址限制器时间间隔
	IpLimitTimes             int                                                     // IP地址限制器时间单位内允许的次数
	DeviceLimitDuration      time.Duration                                           // 设备ID限制器时间间隔
	DeviceLimitTimes         int                                                     // 设备ID限制器时间单位内允许的次数
	ImageCodeExpiresMinutes  int                                                     // 图片验证码过期时间
	VerifyCodeExpiresMinutes int                                                     // 短信验证码过期时间
	ImageCodeMaker           func() string                                           // 图片验证码生成器
	CodeImageMaker           func(imageCode string) []byte                           // 图片验证码的图片生成器
	VerifyCodeMaker          func() string                                           // 短信验证码生成器
	UserIdMaker              func() string                                           // 用户编号生成器
	TokenMaker               func() []byte                                           // Secret的原始随机字符串生成器
	SaltMaker                func() string                                           // Slat生成器
	SecretMaker              func(userId string, token []byte) string                // Secret生成器
	SecretSigner             func(userId, secret, salt string) string                // Secret签名字符串生成器
	PasswordSigner           func(userId, password, salt string) string              // 密码签名字符串生成器
	MessageSender            func(target string, bizName string, args []string) bool // 消息发送接口
	UserTable                UserTable                                               // 数据库用户表配置
	UserDeviceTable          UserDeviceTable                                         // 数据库用户设备关系表配置
}{
	Redis:                    nil,
	DB:                       nil,
	PhoneLimitDuration:       5 * time.Minute,
	PhoneLimitTimes:          10000,
	UserNameLimitDuration:    5 * time.Minute,
	UserNameLimitTimes:       10000,
	IpLimitDuration:          5 * time.Minute,
	IpLimitTimes:             10000,
	DeviceLimitDuration:      5 * time.Minute,
	DeviceLimitTimes:         10000,
	ImageCodeExpiresMinutes:  5,
	VerifyCodeExpiresMinutes: 2,
	ImageCodeMaker:           DefaultImageCodeMaker,
	CodeImageMaker:           DefaultCodeImageMaker,
	VerifyCodeMaker:          DefaultVerifyCodeMaker,
	UserIdMaker:              u.Id8,
	TokenMaker:               DefaultTokenMaker,
	SaltMaker:                DefaultSaltMaker,
	SecretMaker:              DefaultSecretMaker,
	SecretSigner:             DefaultSigner,
	PasswordSigner:           DefaultSigner,
	MessageSender:            nil,
	UserTable: UserTable{
		Table: "User",
		Id:    "id",
		//Name:     "name",
		Phone:    "phone",
		Password: "password",
		Salt:     "salt",
	},
	UserDeviceTable: UserDeviceTable{
		Table:    "UserDevice",
		UserId:   "userId",
		DeviceId: "deviceId",
		Secret:   "secret",
		Salt:     "salt",
	},
}

func Init() {
	if inited {
		return
	}
	inited = true

	if Config.Redis == nil {
		Config.Redis = redis.GetRedis("user", nil)
	}
	if Config.DB == nil {
		Config.DB = db.GetDB("user", nil)
	}
	PhoneLimiter = utility.NewLimiter("Phone", Config.PhoneLimitDuration, Config.PhoneLimitTimes, Config.Redis)
	//UserNameLimiter = utility.NewLimiter("IP", Config.UserNameLimitDuration, Config.UserNameLimitTimes, Config.Redis)
	IpLimiter = utility.NewLimiter("IP", Config.IpLimitDuration, Config.IpLimitTimes, Config.Redis)
	DeviceLimiter = utility.NewLimiter("Device", Config.DeviceLimitDuration, Config.DeviceLimitTimes, Config.Redis)
}

var settedKey = []byte("?GQ$0K0GgLdO=f+~L68PLm$uhKr4'=tV")
var settedIv = []byte("VFs7@sK61cj^f?HZ")
var keysSetted = false

func SetEncryptKeys(key, iv []byte) {
	if !keysSetted {
		settedKey = key
		settedIv = iv
		keysSetted = true
	}
}

var phoneEncryptOffset uint64 = 8767321298 // 手机号加密的偏移量，建议10位数
var phoneEncryptOffsetSetted = false

func SetPhoneEncryptOffset(offset string) {
	if !phoneEncryptOffsetSetted {
		phoneEncryptOffsetSetted = true
		phoneEncryptOffset = u.Uint64(u.DecryptAes(offset, settedKey, settedIv))
	}
}
