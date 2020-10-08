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

// 基于Redis PubSub的分布式本地化Session解决方案

var _sessionStarted = false
var _sessionRedis *redis.Redis
var _sessionLogger *log.Logger
var _sessions = sync.Map{}
var _sessionUsed = make(map[string]bool)
var _sessionAliveSeconds int

type Session struct {
	expires int64
	data    map[string]string
}

func StartSession(startedRedis *redis.Redis, logger *log.Logger, aliveTime time.Duration) {
	if _sessionStarted {
		return
	}
	_sessionStarted = true
	_sessionRedis = startedRedis
	_sessionLogger = logger
	if _sessionLogger == nil {
		_sessionLogger = log.DefaultLogger
	}
	_sessionAliveSeconds = int(aliveTime / time.Second)
	if _sessionAliveSeconds < 30 {
		_sessionAliveSeconds = 30
	}
	resetSession()
	if !_sessionRedis.SubRunning {
		_sessionLogger.Error("redis for session is not start")
	}
	_sessionRedis.Subscribe("_SESSIONS", resetSession, receiveSession)
	go aliveSessions()
}

func SetSession(userId string, fieldAndValues ...interface{}) {
	_sessionRedis.HMSET("_SESSION_"+userId, fieldAndValues...)
	_sessionRedis.EXPIRE("_SESSION_"+userId, _sessionAliveSeconds+5)
	data := map[string]interface{}{"userId": userId}
	if len(fieldAndValues) > 1 {
		for i := 1; i < len(fieldAndValues); i += 2 {
			if k, ok := fieldAndValues[i-1].(string); ok {
				data[k] = fieldAndValues[i]
			}
		}
	}
	encodedData, err := json.Marshal(data)
	if err == nil {
		_sessionRedis.PUBLISH("_SESSIONS", string(encodedData))
	}
}

func GetSession(userId string) *Session {
	sess := getSession(userId)
	_sessionUsed[userId] = true
	return sess
}

func getSession(userId string) *Session {
	sessObj, ok := _sessions.Load(userId)
	var sess *Session
	if ok {
		sess = sessObj.(*Session)
	} else {
		sess = new(Session)
		results := _sessionRedis.HGETALL("_SESSION_" + userId)
		for k, r := range results {
			sess.data[k] = r.String()
		}
		_sessions.Store(userId, sess)
	}
	sess.expires = time.Now().Unix() + int64(_sessionAliveSeconds) + 5
	return sess
}

func aliveSessions() {
	for {
		// 删除过期的数据
		expires := time.Now().Unix()
		_sessions.Range(func(key, value interface{}) bool {
			sess := value.(*Session)
			if sess.expires < expires {
				_sessions.Delete(key)
			}
			return true
		})

		if len(_sessionUsed) > 0 {
			oldSessionUsed := _sessionUsed
			_sessionUsed = make(map[string]bool)
			userIds := make([]string, len(oldSessionUsed))
			i := 0
			for userId := range oldSessionUsed {
				userIds[i] = userId
				i++
				_sessionRedis.EXPIRE("_SESSION_" + userId, _sessionAliveSeconds + 5)
			}
			_sessionRedis.PUBLISH("_SESSIONS", "+"+strings.Join(userIds, ","))
		}

		for i := 0; i < 5; i++ {
			time.Sleep(time.Second)
			if !_sessionRedis.SubRunning {
				break
			}
		}
	}
}

func resetSession() {
	_sessions = sync.Map{}
}

func receiveSession(data []byte) {
	if data == nil || len(data) == 0 {
		return
	}

	if data[0] == '+' {
		// 更新Session生命周期
		userIds := strings.Split(string(data[1:]), ",")
		for _, userId := range userIds {
			sess := getSession(userId)
			sess.expires = time.Now().Unix() + int64(_sessionAliveSeconds) + 5
		}
	}

	receivedData := map[string]interface{}{}
	err := json.Unmarshal(data, &receivedData)
	if err != nil {
		_sessionLogger.Error(err.Error(), "data", string(data))
		return
	}
	if receivedData["userId"] != nil {
		sess := getSession(u.String(receivedData["userId"]))
		for k, v := range receivedData {
			if k != "userId" {
				sess.data[k] = u.String(v)
			}
		}
		sess.expires = time.Now().Unix() + int64(_sessionAliveSeconds) + 5
	}
}
