package user

import (
	"encoding/json"
	"github.com/ssgo/log"
	"github.com/ssgo/redis"
	"github.com/ssgo/u"
	"strings"
	"sync"
	"time"
)

// 基于Redis的分布式本地化Session解决方案

// ----------- Session Serve -----------

type SessionServe struct {
	redis        *redis.Redis
	logger       *log.Logger
	sessions     sync.Map
	used         map[string]bool
	usedLock     sync.Mutex
	aliveSeconds int
}

func StartSession(startedRedis *redis.Redis, logger *log.Logger, aliveTime time.Duration) *SessionServe {
	if logger == nil {
		logger = log.DefaultLogger
	}

	if !startedRedis.SubRunning {
		logger.Error("redis for session is not start")
		return nil
	}

	serve := &SessionServe{
		redis:        startedRedis,
		logger:       logger,
		sessions:     sync.Map{},
		used:         map[string]bool{},
		usedLock:     sync.Mutex{},
		aliveSeconds: int(aliveTime / time.Second),
	}

	if serve.aliveSeconds < 1 {
		serve.aliveSeconds = 1
	}

	// 注册订阅
	serve.redis.Subscribe("_SESSIONS", serve.reset, serve.receiver)

	// 启动生命周期保持器
	go serve.aliveKeeper()

	return serve
}

// 获取一个Session并且设置生命维持标记
func (serve *SessionServe) Get(userId string) *Session {
	sess := serve.get(userId)
	serve.usedLock.Lock()
	serve.used[userId] = true
	serve.usedLock.Unlock()
	return sess
}

// 获取一个Session，不设置生命维持标记
func (serve *SessionServe) get(userId string) *Session {
	sessObj, ok := serve.sessions.Load(userId)
	expires := time.Now().Unix() + int64(serve.aliveSeconds)
	var sess *Session
	if ok {
		sess = sessObj.(*Session)
		sess.expires = expires
	} else {
		sess = &Session{
			userId:      userId,
			expires:     expires,
			lock:        sync.Mutex{},
			data:        nil,
			changedData: map[string]string{},
			serve:       serve,
		}
		serve.sessions.Store(userId, sess)
	}

	if sess.data == nil {
		// 从redis获取完整的数据
		sess.lock.Lock()
		if sess.data == nil {
			results := serve.redis.HGETALL("_SESSION_" + userId)
			sess.data = map[string]string{}
			for k, r := range results {
				sess.data[k] = r.String()
			}
		}
		sess.lock.Unlock()
	}
	return sess
}

func (serve *SessionServe) aliveKeeper() {
	for {
		// 删除过期的数据
		expires := time.Now().Unix()
		serve.sessions.Range(func(key, value interface{}) bool {
			sess := value.(*Session)
			if sess.expires < expires {
				serve.sessions.Delete(key)
			}
			return true
		})

		if len(serve.used) > 0 {
			serve.usedLock.Lock()
			oldSessionUsed := serve.used
			serve.used = make(map[string]bool)
			serve.usedLock.Unlock()
			userIds := make([]string, len(oldSessionUsed))
			i := 0
			for userId := range oldSessionUsed {
				userIds[i] = userId
				i++
				serve.redis.EXPIRE("_SESSION_"+userId, serve.aliveSeconds)
			}
			serve.redis.PUBLISH("_SESSIONS", "+"+strings.Join(userIds, ","))
		}

		for i := 0; i < 5; i++ {
			time.Sleep(time.Second)
			if !serve.redis.SubRunning {
				break
			}
		}
	}
}

func (serve *SessionServe) reset() {
	serve.sessions = sync.Map{}
}

func (serve *SessionServe) receiver(data []byte) {
	if data == nil || len(data) == 0 {
		return
	}

	if data[0] == '+' {
		// 更新Session生命周期
		userIds := strings.Split(string(data[1:]), ",")
		for _, userId := range userIds {
			sess := serve.get(userId)
			sess.expires = time.Now().Unix() + int64(serve.aliveSeconds)
		}
		return
	}

	receivedData := map[string]interface{}{}
	err := json.Unmarshal(data, &receivedData)
	if err != nil {
		serve.logger.Error(err.Error(), "sessions", string(data))
		return
	}
	if receivedData["userId"] != nil {
		sess := serve.get(u.String(receivedData["userId"]))
		for k, v := range receivedData {
			if k != "userId" {
				sess.data[k] = u.String(v)
			}
		}
		sess.expires = time.Now().Unix() + int64(serve.aliveSeconds)
	}
}

// ----------- Session -----------

type Session struct {
	userId      string
	expires     int64
	lock        sync.Mutex
	data        map[string]string
	changedData map[string]string
	serve       *SessionServe
}

func (sess *Session) Set(key string, valueAndMore ...interface{}) {
	if len(valueAndMore) > 0 {
		sess.lock.Lock()
		sess.data[key] = u.String(valueAndMore[0])
		sess.changedData[key] = u.String(valueAndMore[0])
		if len(valueAndMore) > 2 {
			for i := 2; i < len(valueAndMore); i += 2 {
				sess.data[u.String(valueAndMore[i-1])] = u.String(valueAndMore[i])
				sess.changedData[u.String(valueAndMore[i-1])] = u.String(valueAndMore[i])
			}
		}
		sess.lock.Unlock()
	}
}

func (sess *Session) Save() {
	sess.lock.Lock()
	changedData := sess.changedData
	sess.changedData = make(map[string]string)
	sess.lock.Unlock()

	if len(changedData) == 0 {
		return
	}

	args := make([]interface{}, len(changedData)*2)
	i := 0
	for k, v := range changedData {
		args[i] = k
		args[i+1] = v
		i += 2
	}

	changedData["userId"] = sess.userId
	encodedData, err := json.Marshal(changedData)
	if err == nil {
		sess.serve.redis.PUBLISH("_SESSIONS", string(encodedData))
	}

	sess.serve.redis.HMSET("_SESSION_"+sess.userId, args...)
	sess.serve.redis.EXPIRE("_SESSION_"+sess.userId, sess.serve.aliveSeconds)
}

func (sess *Session) Int(key string) int {
	return u.Int(sess.String(key))
}
func (sess *Session) Int64(key string) int64 {
	return u.Int64(sess.String(key))
}
func (sess *Session) Uint(key string) uint {
	return u.Uint(sess.String(key))
}
func (sess *Session) Uint64(key string) uint64 {
	return u.Uint64(sess.String(key))
}
func (sess *Session) Float(key string) float32 {
	return u.Float(sess.String(key))
}
func (sess *Session) Float64(key string) float64 {
	return u.Float64(sess.String(key))
}
func (sess *Session) String(key string) string {
	sess.lock.Lock()
	str := sess.data[key]
	sess.lock.Unlock()
	return str
}
func (sess *Session) Bool(key string) bool {
	return u.Bool(sess.String(key))
}
func (sess *Session) Map(key string) map[string]interface{} {
	target := map[string]interface{}{}
	if err := json.Unmarshal([]byte(sess.String(key)), &target); err != nil {
		sess.serve.logger.Error("failed to decode json value on session", "userId", sess.userId, "sessionKey", key)
	}
	return target
}
func (sess *Session) Arr(key string) []interface{} {
	target := make([]interface{}, 0)
	if err := json.Unmarshal([]byte(sess.String(key)), &target); err != nil {
		sess.serve.logger.Error("failed to decode json value on session", "userId", sess.userId, "sessionKey", key)
	}
	return target
}
func (sess *Session) MapTo(key string, target interface{}) {
	u.Convert(sess.Map(key), &target)
}
func (sess *Session) ArrTo(key string, target interface{}) {
	u.Convert(sess.Arr(key), &target)
}
