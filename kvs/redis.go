package kvs

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var raddr = ""
var rpref = ""

func Init(addr string, prefix string) {
	raddr = addr
	rpref = prefix
}

func con() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     raddr,
		Password: "",
		DB:       0,
	})
}

func k(key string) string {
	return rpref + ":" + key
}

func Set(key, value string, expireSec uint) error {
	err := con().Set(context.Background(), k(key), value, time.Duration(expireSec)*time.Second).Err()

	if err != nil {
		return err
	}
	return nil
}

func Get(key string) (string, error) {
	v, err := con().Get(context.Background(), k(key)).Result()
	if err != nil {
		return "", err
	}
	return v, nil
}

func Del(key string) {
	con().Del(context.Background(), k(key))
}
