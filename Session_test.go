package user_test

import (
	"github.com/ssdo/user"
	"github.com/ssgo/redis"
	"testing"
)

func TestSession(t *testing.T) {
	rd1 := redis.GetRedis("test", nil)
	rd2 := redis.GetRedis("test", nil)
	rd1.Start()
	rd2.Start()

	sessionServe1 := user.StartSession(rd1, nil, 1)
	sessionServe2 := user.StartSession(rd2, nil, 1)

	// 先存后取
	a1 := sessionServe1.Get("aaa")
	a1.Set("name", "AAA")
	a1.Save()

	a2 := sessionServe2.Get("aaa")

	if a2.String("name") != "AAA" {
		t.Fatal("aaa name error on session2", a2.String("name"))
	}

	// 先取后存
	b1 := sessionServe1.Get("bbb")
	b2 := sessionServe2.Get("bbb")

	b1.Set("name", "BBB")
	b1.Save()

	//time.Sleep(20 * time.Millisecond)
	if b2.String("name") != "BBB" {
		t.Fatal("bbb name error on session2", b2.String("name"))
	}

	// 反向
	b2.Set("age", 11, "name", "BBBB")
	b2.Save()

	//time.Sleep(5 * time.Millisecond)

	if b1.String("name") != "BBBB" {
		t.Fatal("bbb name error on session1", b1.String("name"))
	}

	rd1.Stop()
	rd2.Stop()
}
