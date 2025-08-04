package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
	"go.uber.org/zap"
)

type ValkeyCache struct {
	client valkey.Client
	logger *zap.Logger
	prefix string
}

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
	Prefix   string
}

func NewValkeyCache(config Config, logger *zap.Logger) (*ValkeyCache, error) {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{fmt.Sprintf("%s:%d", config.Host, config.Port)},
		Password:    config.Password,
		SelectDB:    config.DB,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Valkey client: %w", err)
	}

	cache := &ValkeyCache{
		client: client,
		logger: logger,
		prefix: config.Prefix,
	}

	if err := cache.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping Valkey: %w", err)
	}

	logger.Info("Valkey cache client created successfully",
		zap.String("host", config.Host),
		zap.Int("port", config.Port),
		zap.String("prefix", config.Prefix))

	return cache, nil
}

func (c *ValkeyCache) Ping(ctx context.Context) error {
	cmd := c.client.B().Ping().Build()
	result := c.client.Do(ctx, cmd)
	return result.Error()
}

func (c *ValkeyCache) buildKey(tenantID, key string) string {
	if c.prefix != "" {
		return fmt.Sprintf("%s:tenant:%s:%s", c.prefix, tenantID, key)
	}
	return fmt.Sprintf("tenant:%s:%s", tenantID, key)
}

func (c *ValkeyCache) Set(ctx context.Context, tenantID, key string, value interface{}, expiration time.Duration) error {
	fullKey := c.buildKey(tenantID, key)

	var cmd valkey.Completed
	if expiration > 0 {
		cmd = c.client.B().Set().Key(fullKey).Value(fmt.Sprintf("%v", value)).Ex(expiration).Build()
	} else {
		cmd = c.client.B().Set().Key(fullKey).Value(fmt.Sprintf("%v", value)).Build()
	}

	result := c.client.Do(ctx, cmd)
	if err := result.Error(); err != nil {
		c.logger.Error("Failed to set cache value",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Error(err))
		return err
	}

	return nil
}

func (c *ValkeyCache) Get(ctx context.Context, tenantID, key string) (string, error) {
	fullKey := c.buildKey(tenantID, key)

	cmd := c.client.B().Get().Key(fullKey).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return "", ErrCacheMiss
		}
		c.logger.Error("Failed to get cache value",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Error(err))
		return "", err
	}

	value, err := result.ToString()
	if err != nil {
		return "", fmt.Errorf("failed to convert result to string: %w", err)
	}

	return value, nil
}

func (c *ValkeyCache) Delete(ctx context.Context, tenantID, key string) error {
	fullKey := c.buildKey(tenantID, key)

	cmd := c.client.B().Del().Key(fullKey).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		c.logger.Error("Failed to delete cache value",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Error(err))
		return err
	}

	return nil
}

func (c *ValkeyCache) Exists(ctx context.Context, tenantID, key string) (bool, error) {
	fullKey := c.buildKey(tenantID, key)

	cmd := c.client.B().Exists().Key(fullKey).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		c.logger.Error("Failed to check cache key existence",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Error(err))
		return false, err
	}

	count, err := result.AsInt64()
	if err != nil {
		return false, fmt.Errorf("failed to convert result to int64: %w", err)
	}

	return count > 0, nil
}

func (c *ValkeyCache) SetExpire(ctx context.Context, tenantID, key string, expiration time.Duration) error {
	fullKey := c.buildKey(tenantID, key)

	cmd := c.client.B().Expire().Key(fullKey).Seconds(int64(expiration.Seconds())).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		c.logger.Error("Failed to set cache key expiration",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Duration("expiration", expiration),
			zap.Error(err))
		return err
	}

	return nil
}

func (c *ValkeyCache) GetTTL(ctx context.Context, tenantID, key string) (time.Duration, error) {
	fullKey := c.buildKey(tenantID, key)

	cmd := c.client.B().Ttl().Key(fullKey).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		c.logger.Error("Failed to get cache key TTL",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Error(err))
		return 0, err
	}

	seconds, err := result.AsInt64()
	if err != nil {
		return 0, fmt.Errorf("failed to convert result to int64: %w", err)
	}

	if seconds == -1 {
		return -1, nil
	}
	if seconds == -2 {
		return 0, ErrCacheMiss
	}

	return time.Duration(seconds) * time.Second, nil
}

func (c *ValkeyCache) FlushTenant(ctx context.Context, tenantID string) error {
	pattern := c.buildKey(tenantID, "*")

	cmd := c.client.B().Scan().Cursor(0).Match(pattern).Count(1000).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		c.logger.Error("Failed to scan cache keys for tenant",
			zap.String("tenant_id", tenantID),
			zap.Error(err))
		return err
	}

	scanResult, err := result.AsScanEntry()
	if err != nil {
		return fmt.Errorf("failed to parse scan result: %w", err)
	}

	if len(scanResult.Elements) > 0 {
		delCmd := c.client.B().Del().Key(scanResult.Elements...).Build()
		delResult := c.client.Do(ctx, delCmd)

		if err := delResult.Error(); err != nil {
			c.logger.Error("Failed to delete tenant cache keys",
				zap.String("tenant_id", tenantID),
				zap.Int("key_count", len(scanResult.Elements)),
				zap.Error(err))
			return err
		}

		c.logger.Info("Flushed tenant cache",
			zap.String("tenant_id", tenantID),
			zap.Int("keys_deleted", len(scanResult.Elements)))
	}

	return nil
}

func (c *ValkeyCache) SetHash(ctx context.Context, tenantID, key string, fields map[string]interface{}) error {
	fullKey := c.buildKey(tenantID, key)

	var args []string
	for field, value := range fields {
		args = append(args, field, fmt.Sprintf("%v", value))
	}

	if len(args) == 0 {
		return fmt.Errorf("no fields provided for hash")
	}

	cmd := c.client.B().Hmset().Key(fullKey).FieldValue().FieldValue(args[0], args[1])
	for i := 2; i < len(args); i += 2 {
		cmd = cmd.FieldValue(args[i], args[i+1])
	}

	result := c.client.Do(ctx, cmd.Build())
	if err := result.Error(); err != nil {
		c.logger.Error("Failed to set cache hash",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.Error(err))
		return err
	}

	return nil
}

func (c *ValkeyCache) GetHashField(ctx context.Context, tenantID, key, field string) (string, error) {
	fullKey := c.buildKey(tenantID, key)

	cmd := c.client.B().Hget().Key(fullKey).Field(field).Build()
	result := c.client.Do(ctx, cmd)

	if err := result.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return "", ErrCacheMiss
		}
		c.logger.Error("Failed to get cache hash field",
			zap.String("tenant_id", tenantID),
			zap.String("key", key),
			zap.String("field", field),
			zap.Error(err))
		return "", err
	}

	value, err := result.ToString()
	if err != nil {
		return "", fmt.Errorf("failed to convert result to string: %w", err)
	}

	return value, nil
}

func (c *ValkeyCache) Close() {
	c.client.Close()
	c.logger.Info("Valkey cache client closed")
}

func (c *ValkeyCache) Health(ctx context.Context) error {
	return c.Ping(ctx)
}

var ErrCacheMiss = fmt.Errorf("cache miss")

type CacheInterface interface {
	Set(ctx context.Context, tenantID, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, tenantID, key string) (string, error)
	Delete(ctx context.Context, tenantID, key string) error
	Exists(ctx context.Context, tenantID, key string) (bool, error)
	SetExpire(ctx context.Context, tenantID, key string, expiration time.Duration) error
	GetTTL(ctx context.Context, tenantID, key string) (time.Duration, error)
	FlushTenant(ctx context.Context, tenantID string) error
	SetHash(ctx context.Context, tenantID, key string, fields map[string]interface{}) error
	GetHashField(ctx context.Context, tenantID, key, field string) (string, error)
	Health(ctx context.Context) error
	Close()
}
