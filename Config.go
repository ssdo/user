package user

import (
	"github.com/ssgo/db"
	"github.com/ssgo/redis"
	"github.com/ssgo/u"
	"time"
)

type Result uint8

const (
	OK Result = iota
	PhoneLimited
	DeviceLimited
	IpLimited
	StoreFailed
	MakeFailed
	SendFailed
	AuthFailed
)

// 用户表
type TableUser struct {
	Table string // 表名
	Id    string // id字段名
	//Name     string // 用户名字段名
	Phone    string // 手机号字段名
	Password string // 密码字段名
	Salt     string // 用于计算密码的salt字段名
}

// 用户设备关系表
type TableSecret struct {
	Table    string // 表名
	UserId   string // 用户id字段名
	DeviceId string // 设备id字段名
	Secret   string // 密码字段名
	Salt     string // 用于计算密码的salt字段名
}

type Config struct {
	Redis                    *redis.Redis                                   // Redis连接池
	DB                       *db.DB                                         // 数据库连接池
	PhoneLimitDuration       time.Duration                                  // 手机号限制器时间间隔
	PhoneLimitTimes          int                                            // 手机号限制器时间单位内允许的次数
	UserNameLimitDuration    time.Duration                                  // 用户名限制器时间间隔
	UserNameLimitTimes       int                                            // 用户名限制器时间单位内允许的次数
	IpLimitDuration          time.Duration                                  // IP地址限制器时间间隔
	IpLimitTimes             int                                            // IP地址限制器时间单位内允许的次数
	DeviceLimitDuration      time.Duration                                  // 设备ID限制器时间间隔
	DeviceLimitTimes         int                                            // 设备ID限制器时间单位内允许的次数
	ImageCodeExpiresMinutes  int                                            // 图片验证码过期时间
	VerifyCodeExpiresMinutes int                                            // 短信验证码过期时间
	ImageCodeMaker  func() string                                           // 图片验证码生成器
	CodeImageMaker  func(imageCode string) []byte                           // 图片验证码的图片生成器
	VerifyCodeMaker func() string                                           // 短信验证码生成器
	UserIdMaker     func() string                                           // 用户编号生成器
	TokenMaker      func() []byte                                           // Secret的原始随机字符串生成器
	SaltMaker       func() string                                           // Slat生成器
	SecretMaker     func(userId string, token []byte) string                // Secret生成器
	SecretSigner    func(userId, secret, salt string) string                // Secret签名字符串生成器
	PasswordSigner  func(userId, password, salt string) string              // 密码签名字符串生成器
	MessageSender   func(target string, bizName string, args []string) bool // 消息发送接口
	TableUser       TableUser                                               // 数据库用户表配置
	TableSecret     TableSecret                                             // 数据库用户设备关系表配置
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
