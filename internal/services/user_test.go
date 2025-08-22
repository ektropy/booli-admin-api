package services

import (
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomPassword(t *testing.T) {
	password, err := generateRandomPassword()
	
	assert.NoError(t, err)
	assert.NotEmpty(t, password)
	assert.GreaterOrEqual(t, len(password), 12)
	
	password2, err2 := generateRandomPassword()
	assert.NoError(t, err2)
	assert.NotEqual(t, password, password2)
}

func TestFilterUsers(t *testing.T) {
	service := &UserService{}
	
	users := []models.User{
		{Username: "alice", Email: "alice@example.com", Enabled: true},
		{Username: "bob", Email: "bob@example.com", Enabled: false},
		{Username: "charlie", Email: "charlie@test.com", Enabled: true},
	}
	
	t.Run("filter by enabled status", func(t *testing.T) {
		request := &models.UserSearchRequest{
			Enabled: boolPtr(true),
		}
		
		filtered := service.filterUsers(users, request)
		assert.Len(t, filtered, 2)
		assert.Equal(t, "alice", filtered[0].Username)
		assert.Equal(t, "charlie", filtered[1].Username)
	})
	
	t.Run("filter by search term", func(t *testing.T) {
		request := &models.UserSearchRequest{
			Search: "ali",
		}
		
		filtered := service.filterUsers(users, request)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "alice", filtered[0].Username)
	})
	
	t.Run("no filters", func(t *testing.T) {
		request := &models.UserSearchRequest{}
		
		filtered := service.filterUsers(users, request)
		assert.Len(t, filtered, 3)
	})
}

func boolPtr(b bool) *bool {
	return &b
}