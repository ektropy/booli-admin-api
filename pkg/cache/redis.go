package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(client *redis.Client) *RedisCache {
	return &RedisCache{
		client: client,
	}
}

func (r *RedisCache) getTenantKey(tenantID, key string) string {
	return fmt.Sprintf("tenant:%s:%s", tenantID, key)
}

func (r *RedisCache) Set(ctx context.Context, tenantID, key string, value interface{}, expiration time.Duration) error {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.Set(ctx, tenantKey, data, expiration).Err()
}

func (r *RedisCache) Get(ctx context.Context, tenantID, key string, dest interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := r.client.Get(ctx, tenantKey).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return fmt.Errorf("failed to get value from cache: %w", err)
	}

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

func (r *RedisCache) Delete(ctx context.Context, tenantID, key string) error {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.Del(ctx, tenantKey).Err()
}

func (r *RedisCache) Exists(ctx context.Context, tenantID, key string) (bool, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	count, err := r.client.Exists(ctx, tenantKey).Result()
	return count > 0, err
}

func (r *RedisCache) SetNX(ctx context.Context, tenantID, key string, value interface{}, expiration time.Duration) (bool, error) {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.SetNX(ctx, tenantKey, data, expiration).Result()
}

func (r *RedisCache) GetTTL(ctx context.Context, tenantID, key string) (time.Duration, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.TTL(ctx, tenantKey).Result()
}

func (r *RedisCache) Expire(ctx context.Context, tenantID, key string, expiration time.Duration) error {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.Expire(ctx, tenantKey, expiration).Err()
}

func (r *RedisCache) FlushTenant(ctx context.Context, tenantID string) error {
	pattern := r.getTenantKey(tenantID, "*")

	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	var keys []string

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}

	return nil
}

func (r *RedisCache) SetHash(ctx context.Context, tenantID, key, field string, value interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.HSet(ctx, tenantKey, field, data).Err()
}

func (r *RedisCache) GetHash(ctx context.Context, tenantID, key, field string, dest interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := r.client.HGet(ctx, tenantKey, field).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return fmt.Errorf("failed to get hash field: %w", err)
	}

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

func (r *RedisCache) DeleteHash(ctx context.Context, tenantID, key, field string) error {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.HDel(ctx, tenantKey, field).Err()
}

func (r *RedisCache) GetAllHash(ctx context.Context, tenantID, key string) (map[string]string, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.HGetAll(ctx, tenantKey).Result()
}

func (r *RedisCache) IncrBy(ctx context.Context, tenantID, key string, value int64) (int64, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.IncrBy(ctx, tenantKey, value).Result()
}

func (r *RedisCache) DecrBy(ctx context.Context, tenantID, key string, value int64) (int64, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.DecrBy(ctx, tenantKey, value).Result()
}

func (r *RedisCache) SetList(ctx context.Context, tenantID, key string, values ...interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	var serializedValues []interface{}
	for _, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		serializedValues = append(serializedValues, data)
	}

	return r.client.LPush(ctx, tenantKey, serializedValues...).Err()
}

func (r *RedisCache) GetList(ctx context.Context, tenantID, key string, start, stop int64) ([]string, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.LRange(ctx, tenantKey, start, stop).Result()
}

func (r *RedisCache) RemoveFromList(ctx context.Context, tenantID, key string, count int64, value interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.LRem(ctx, tenantKey, count, data).Err()
}

func (r *RedisCache) AddToSet(ctx context.Context, tenantID, key string, members ...interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	var serializedMembers []interface{}
	for _, member := range members {
		data, err := json.Marshal(member)
		if err != nil {
			return fmt.Errorf("failed to marshal member: %w", err)
		}
		serializedMembers = append(serializedMembers, data)
	}

	return r.client.SAdd(ctx, tenantKey, serializedMembers...).Err()
}

func (r *RedisCache) IsMemberOfSet(ctx context.Context, tenantID, key string, member interface{}) (bool, error) {
	tenantKey := r.getTenantKey(tenantID, key)

	data, err := json.Marshal(member)
	if err != nil {
		return false, fmt.Errorf("failed to marshal member: %w", err)
	}

	return r.client.SIsMember(ctx, tenantKey, data).Result()
}

func (r *RedisCache) RemoveFromSet(ctx context.Context, tenantID, key string, members ...interface{}) error {
	tenantKey := r.getTenantKey(tenantID, key)

	var serializedMembers []interface{}
	for _, member := range members {
		data, err := json.Marshal(member)
		if err != nil {
			return fmt.Errorf("failed to marshal member: %w", err)
		}
		serializedMembers = append(serializedMembers, data)
	}

	return r.client.SRem(ctx, tenantKey, serializedMembers...).Err()
}

func (r *RedisCache) GetSetMembers(ctx context.Context, tenantID, key string) ([]string, error) {
	tenantKey := r.getTenantKey(tenantID, key)
	return r.client.SMembers(ctx, tenantKey).Result()
}

func (r *RedisCache) Lock(ctx context.Context, tenantID, key string, expiration time.Duration) (bool, error) {
	lockKey := r.getTenantKey(tenantID, fmt.Sprintf("lock:%s", key))
	return r.client.SetNX(ctx, lockKey, "locked", expiration).Result()
}

func (r *RedisCache) Unlock(ctx context.Context, tenantID, key string) error {
	lockKey := r.getTenantKey(tenantID, fmt.Sprintf("lock:%s", key))
	return r.client.Del(ctx, lockKey).Err()
}

func (r *RedisCache) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *RedisCache) Close() error {
	return r.client.Close()
}
