package aerospike_test

import (
	"context"
	"strings"
	"testing"
	"time"

	plugin "github.com/G-Research/vault-plugin-database-aerospike"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
)

func TestCreateUser(t *testing.T) {
	userCreated := false
	createdUsername := ""
	createdPassword := ""
	createdRoles := []string{}
	clientFactory := &MockClientFactory{
		OnCreateUser: func(user string, password string, roles []string) {
			userCreated = true
			createdUsername = user
			createdPassword = password
			createdRoles = roles
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": ["read", "user-admin"] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	username, password, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	if err != nil {
		t.Errorf("Error creating user: %s", err)
	}
	if !userCreated {
		t.Error("Expected user to have been created")
	}
	if username != createdUsername {
		t.Errorf("Returned username '%s' does not match created username '%s'", username, createdUsername)
	}
	if password != createdPassword {
		t.Errorf("Returned password '%s' does not match created password '%s'", password, createdPassword)
	}
	for _, expectedRole := range []string{"read", "user-admin"} {
		if !contains(createdRoles, expectedRole) {
			t.Errorf("Expected created roles '%s' to contain role '%s'", createdRoles, expectedRole)
		}
	}
}

func TestCreateUserWithName(t *testing.T) {
	userCreated := false
	clientFactory := &MockClientFactory{
		OnCreateUser: func(user string, password string, roles []string) {
			userCreated = true
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": ["read", "user-admin"] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "testdisplay",
		RoleName:    "testrole",
	}

	username, _, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	if err != nil {
		t.Errorf("Error creating user: %s", err)
	}
	if !userCreated {
		t.Error("Expected user to have been created")
	}
	if !strings.Contains(username, "testdisplay") {
		t.Errorf("Expected username to contain 'testdisplay' but was '%s'", username)
	}
	if !strings.Contains(username, "testrole") {
		t.Errorf("Expected username to contain 'testrole' but was '%s'", username)
	}
}

func TestCreateUserWithoutCreateStatement(t *testing.T) {
	userCreated := false
	clientFactory := &MockClientFactory{
		OnCreateUser: func(user string, password string, roles []string) {
			userCreated = true
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{}
	usernameConfig := dbplugin.UsernameConfig{}

	_, _, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	expectedError := dbutil.ErrEmptyCreationStatement.Error()
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s' but was '%s'", expectedError, err.Error())
	}
	if userCreated {
		t.Error("Expected user to not have been created")
	}
}

func TestCreateUserWithInvalidJsonStatement(t *testing.T) {
	userCreated := false
	clientFactory := &MockClientFactory{
		OnCreateUser: func(user string, password string, roles []string) {
			userCreated = true
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`invalid_json`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	_, _, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	if err == nil {
		t.Errorf("Expected to receive an error but it was nil")
	}
	if userCreated {
		t.Error("Expected user to not have been created")
	}
}

func TestCreateUserWithEmptyRoles(t *testing.T) {
	userCreated := false
	clientFactory := &MockClientFactory{
		OnCreateUser: func(user string, password string, roles []string) {
			userCreated = true
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": [] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	_, _, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	expectedError := "roles array is required in creation statement"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s' but was '%s'", expectedError, err.Error())
	}
	if userCreated {
		t.Error("Expected user to not have been created")
	}
}

func initialisePlugin(t *testing.T, clientFactory *MockClientFactory) dbplugin.Database {
	aerospike, err := plugin.New(clientFactory)
	if err != nil {
		t.Errorf("Error creating Aerospike plugin: %s", err)
	}
	aerospikePlugin := aerospike.(dbplugin.Database)
	ctx := context.Background()
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": "test_user",
		"password": "test_password",
	}
	_, err = aerospikePlugin.Init(ctx, config, false)
	if err != nil {
		t.Errorf("Error initialising Aerospike plugin: %s", err)
	}
	return aerospikePlugin
}

func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
