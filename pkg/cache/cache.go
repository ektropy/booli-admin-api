package cache

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrCacheMiss = errors.New("cache miss")

type Cache interface {
	Set(ctx context.Context, tenantID, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, tenantID, key string, dest interface{}) error
	Delete(ctx context.Context, tenantID, key string) error
	Exists(ctx context.Context, tenantID, key string) (bool, error)

	SetNX(ctx context.Context, tenantID, key string, value interface{}, expiration time.Duration) (bool, error)
	GetTTL(ctx context.Context, tenantID, key string) (time.Duration, error)
	Expire(ctx context.Context, tenantID, key string, expiration time.Duration) error

	FlushTenant(ctx context.Context, tenantID string) error

	SetHash(ctx context.Context, tenantID, key, field string, value interface{}) error
	GetHash(ctx context.Context, tenantID, key, field string, dest interface{}) error
	DeleteHash(ctx context.Context, tenantID, key, field string) error
	GetAllHash(ctx context.Context, tenantID, key string) (map[string]string, error)

	IncrBy(ctx context.Context, tenantID, key string, value int64) (int64, error)
	DecrBy(ctx context.Context, tenantID, key string, value int64) (int64, error)

	SetList(ctx context.Context, tenantID, key string, values ...interface{}) error
	GetList(ctx context.Context, tenantID, key string, start, stop int64) ([]string, error)
	RemoveFromList(ctx context.Context, tenantID, key string, count int64, value interface{}) error

	AddToSet(ctx context.Context, tenantID, key string, members ...interface{}) error
	IsMemberOfSet(ctx context.Context, tenantID, key string, member interface{}) (bool, error)
	RemoveFromSet(ctx context.Context, tenantID, key string, members ...interface{}) error
	GetSetMembers(ctx context.Context, tenantID, key string) ([]string, error)

	Lock(ctx context.Context, tenantID, key string, expiration time.Duration) (bool, error)
	Unlock(ctx context.Context, tenantID, key string) error

	Ping(ctx context.Context) error
	Close() error
}

type CacheManager struct {
	cache Cache
}

func NewCacheManager(cache Cache) *CacheManager {
	return &CacheManager{
		cache: cache,
	}
}

var CacheKeys = struct {
	User         string
	UserList     string
	UserRoles    string
	Role         string
	RoleList     string
	Tenant       string
	TenantConfig string
	SSOProvider  string
	SSOProviders string
	Session      string
	Permissions  string
	AuditStats   string
}{
	User:         "user:%s",
	UserList:     "users:list:%s",
	UserRoles:    "user:%s:roles",
	Role:         "role:%s",
	RoleList:     "roles:list",
	Tenant:       "tenant:%s",
	TenantConfig: "tenant:config",
	SSOProvider:  "sso:provider:%s",
	SSOProviders: "sso:providers",
	Session:      "session:%s",
	Permissions:  "user:%s:permissions",
	AuditStats:   "audit:stats:%s",
}

var DefaultTTL = struct {
	Short   time.Duration
	Medium  time.Duration
	Long    time.Duration
	Session time.Duration
}{
	Short:   5 * time.Minute,
	Medium:  30 * time.Minute,
	Long:    2 * time.Hour,
	Session: 24 * time.Hour,
}

func (cm *CacheManager) SetUser(ctx context.Context, tenantID, userID string, user interface{}) error {
	key := fmt.Sprintf(CacheKeys.User, userID)
	return cm.cache.Set(ctx, tenantID, key, user, DefaultTTL.Medium)
}

func (cm *CacheManager) GetUser(ctx context.Context, tenantID, userID string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.User, userID)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) DeleteUser(ctx context.Context, tenantID, userID string) error {
	key := fmt.Sprintf(CacheKeys.User, userID)
	return cm.cache.Delete(ctx, tenantID, key)
}

func (cm *CacheManager) SetUserList(ctx context.Context, tenantID, listKey string, users interface{}) error {
	key := fmt.Sprintf(CacheKeys.UserList, listKey)
	return cm.cache.Set(ctx, tenantID, key, users, DefaultTTL.Short)
}

func (cm *CacheManager) GetUserList(ctx context.Context, tenantID, listKey string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.UserList, listKey)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) SetUserRoles(ctx context.Context, tenantID, userID string, roles interface{}) error {
	key := fmt.Sprintf(CacheKeys.UserRoles, userID)
	return cm.cache.Set(ctx, tenantID, key, roles, DefaultTTL.Medium)
}

func (cm *CacheManager) GetUserRoles(ctx context.Context, tenantID, userID string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.UserRoles, userID)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) SetRole(ctx context.Context, tenantID, roleID string, role interface{}) error {
	key := fmt.Sprintf(CacheKeys.Role, roleID)
	return cm.cache.Set(ctx, tenantID, key, role, DefaultTTL.Long)
}

func (cm *CacheManager) GetRole(ctx context.Context, tenantID, roleID string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.Role, roleID)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) SetTenantConfig(ctx context.Context, tenantID string, config interface{}) error {
	return cm.cache.Set(ctx, tenantID, CacheKeys.TenantConfig, config, DefaultTTL.Long)
}

func (cm *CacheManager) GetTenantConfig(ctx context.Context, tenantID string, dest interface{}) error {
	return cm.cache.Get(ctx, tenantID, CacheKeys.TenantConfig, dest)
}

func (cm *CacheManager) SetSSOProvider(ctx context.Context, tenantID, providerID string, provider interface{}) error {
	key := fmt.Sprintf(CacheKeys.SSOProvider, providerID)
	return cm.cache.Set(ctx, tenantID, key, provider, DefaultTTL.Long)
}

func (cm *CacheManager) GetSSOProvider(ctx context.Context, tenantID, providerID string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.SSOProvider, providerID)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) SetUserPermissions(ctx context.Context, tenantID, userID string, permissions interface{}) error {
	key := fmt.Sprintf(CacheKeys.Permissions, userID)
	return cm.cache.Set(ctx, tenantID, key, permissions, DefaultTTL.Medium)
}

func (cm *CacheManager) GetUserPermissions(ctx context.Context, tenantID, userID string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.Permissions, userID)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) SetSession(ctx context.Context, tenantID, sessionID string, session interface{}) error {
	key := fmt.Sprintf(CacheKeys.Session, sessionID)
	return cm.cache.Set(ctx, tenantID, key, session, DefaultTTL.Session)
}

func (cm *CacheManager) GetSession(ctx context.Context, tenantID, sessionID string, dest interface{}) error {
	key := fmt.Sprintf(CacheKeys.Session, sessionID)
	return cm.cache.Get(ctx, tenantID, key, dest)
}

func (cm *CacheManager) DeleteSession(ctx context.Context, tenantID, sessionID string) error {
	key := fmt.Sprintf(CacheKeys.Session, sessionID)
	return cm.cache.Delete(ctx, tenantID, key)
}

func (cm *CacheManager) InvalidateUserCache(ctx context.Context, tenantID, userID string) error {
	keys := []string{
		fmt.Sprintf(CacheKeys.User, userID),
		fmt.Sprintf(CacheKeys.UserRoles, userID),
		fmt.Sprintf(CacheKeys.Permissions, userID),
	}

	for _, key := range keys {
		if err := cm.cache.Delete(ctx, tenantID, key); err != nil {
			continue
		}
	}

	return cm.cache.Delete(ctx, tenantID, "users:list:*")
}

func (cm *CacheManager) InvalidateRoleCache(ctx context.Context, tenantID, roleID string) error {
	key := fmt.Sprintf(CacheKeys.Role, roleID)
	if err := cm.cache.Delete(ctx, tenantID, key); err != nil {
		return err
	}

	_ = cm.cache.Delete(ctx, tenantID, CacheKeys.RoleList)
	return cm.cache.Delete(ctx, tenantID, "user:*:permissions")
}

func (cm *CacheManager) InvalidateTenantCache(ctx context.Context, tenantID string) error {
	return cm.cache.FlushTenant(ctx, tenantID)
}

func (cm *CacheManager) Lock(ctx context.Context, tenantID, resource string, expiration time.Duration) (bool, error) {
	return cm.cache.Lock(ctx, tenantID, resource, expiration)
}

func (cm *CacheManager) Unlock(ctx context.Context, tenantID, resource string) error {
	return cm.cache.Unlock(ctx, tenantID, resource)
}

func (cm *CacheManager) WithLock(ctx context.Context, tenantID, resource string, expiration time.Duration, fn func() error) error {
	acquired, err := cm.Lock(ctx, tenantID, resource, expiration)
	if err != nil {
		return err
	}

	if !acquired {
		return errors.New("failed to acquire lock")
	}

	defer cm.Unlock(ctx, tenantID, resource)
	return fn()
}
