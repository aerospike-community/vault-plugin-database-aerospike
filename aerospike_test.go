package aerospike_test

import (
	"context"
	"errors"
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
		OnCreateUser: func(user string, password string, roles []string) error {
			userCreated = true
			createdUsername = user
			createdPassword = password
			createdRoles = roles
			return nil
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
		OnCreateUser: func(user string, password string, roles []string) error {
			userCreated = true
			return nil
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
		OnCreateUser: func(user string, password string, roles []string) error {
			userCreated = true
			return nil
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{}
	usernameConfig := dbplugin.UsernameConfig{}

	_, _, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	expectedError := dbutil.ErrEmptyCreationStatement.Error()
	if err == nil {
		t.Errorf("Expected error to be non nil")
	}
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
		OnCreateUser: func(user string, password string, roles []string) error {
			userCreated = true
			return nil
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
		OnCreateUser: func(user string, password string, roles []string) error {
			userCreated = true
			return nil
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
	if err == nil {
		t.Errorf("Expected error to be non nil")
	}
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s' but was '%s'", expectedError, err.Error())
	}
	if userCreated {
		t.Error("Expected user to not have been created")
	}
}

func TestCreateUserWithDbError(t *testing.T) {
	errorMessage := "Aerospike error creating user"
	clientFactory := &MockClientFactory{
		OnCreateUser: func(user string, password string, roles []string) error {
			return errors.New(errorMessage)
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": ["read", "user-admin"] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	_, _, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)

	if err == nil {
		t.Errorf("Expected error to be non nil")
	}
	if err.Error() != errorMessage {
		t.Errorf("Expected error '%s' but was '%s'", errorMessage, err.Error())
	}
}

func TestSetCredentials(t *testing.T) {
	passwordChanged := false
	changePasswordUser := ""
	changePasswordPassword := ""
	clientFactory := &MockClientFactory{
		OnChangePassword: func(user string, password string) error {
			passwordChanged = true
			changePasswordUser = user
			changePasswordPassword = password
			return nil
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	statements := dbplugin.Statements{}
	expectedUser := "test_user"
	expectedPassword := "test_password"
	user := dbplugin.StaticUserConfig{
		Username: expectedUser,
		Password: expectedPassword,
	}

	username, password, err := plugin.SetCredentials(ctx, statements, user)

	if err != nil {
		t.Errorf("Error creating user: %s", err)
	}
	if !passwordChanged {
		t.Error("Password was not changed")
	}
	if changePasswordUser != expectedUser {
		t.Errorf("Expected ChangePassword to be called with user '%s' but was '%s'", expectedUser, changePasswordUser)
	}
	if changePasswordPassword != expectedPassword {
		t.Errorf("Expected ChangePassword to be called with user '%s' but was '%s'", expectedPassword, changePasswordPassword)
	}
	if username != expectedUser {
		t.Errorf("Expected returned user to be '%s' but was '%s'", expectedUser, changePasswordUser)
	}
	if password != expectedPassword {
		t.Errorf("Expected returned password to be '%s' but was '%s'", expectedPassword, changePasswordPassword)
	}
}

func TestSetCredentialsWithDbError(t *testing.T) {
	errorMessage := "Aerospike error changing password"
	clientFactory := &MockClientFactory{
		OnChangePassword: func(user string, password string) error {
			return errors.New(errorMessage)
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	statements := dbplugin.Statements{}
	user := dbplugin.StaticUserConfig{
		Username: "test_user",
		Password: "test_password",
	}

	_, _, err := plugin.SetCredentials(ctx, statements, user)

	if err == nil {
		t.Errorf("Expected error to be non nil")
	}
	if err.Error() != errorMessage {
		t.Errorf("Expected error '%s' but was '%s'", errorMessage, err.Error())
	}
}

func TestRenewUser(t *testing.T) {
	clientFactory := &MockClientFactory{}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	statements := dbplugin.Statements{}
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)

	err := plugin.RenewUser(ctx, statements, "test_user", expiration)

	if err != nil {
		t.Errorf("Error renewing user: %s", err)
	}
}

func TestRevokeUser(t *testing.T) {
	userDropped := false
	droppedUser := ""
	clientFactory := &MockClientFactory{
		OnDropUser: func(user string) error {
			userDropped = true
			droppedUser = user
			return nil
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	ctx := context.Background()
	statements := dbplugin.Statements{}
	userToDrop := "test_user"

	err := plugin.RevokeUser(ctx, statements, userToDrop)

	if err != nil {
		t.Errorf("Error revoking user: %s", err)
	}
	if !userDropped {
		t.Error("User was not dropped")
	}
	if droppedUser != userToDrop {
		t.Errorf("Expected dropped user to be '%s' but was '%s'", userToDrop, droppedUser)
	}
}

func TestRevokeUserWithDbError(t *testing.T) {
	errorMessage := "Aerospike error dropping user"
	clientFactory := &MockClientFactory{
		OnDropUser: func(user string) error {
			return errors.New(errorMessage)
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	err := plugin.RevokeUser(context.Background(), dbplugin.Statements{}, "test_user")

	if err == nil {
		t.Errorf("Expected error to be non nil")
	}
	if err.Error() != errorMessage {
		t.Errorf("Expected error '%s' but was '%s'", errorMessage, err.Error())
	}
}

func TestRotateRootCredentials(t *testing.T) {
	passwordChanged := false
	changePasswordUser := ""
	changePasswordPassword := ""
	clientFactory := &MockClientFactory{
		OnChangePassword: func(user string, password string) error {
			passwordChanged = true
			changePasswordUser = user
			changePasswordPassword = password
			return nil
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	newConfig, err := plugin.RotateRootCredentials(context.Background(), []string{})

	expectedUser := "test_admin_user"
	if err != nil {
		t.Errorf("Error rotating root credentials: %s", err)
	}
	if !passwordChanged {
		t.Error("Root password was not changed")
	}
	if changePasswordUser != expectedUser {
		t.Errorf("Expected ChangePassword to be called with user '%s' but was '%s'", expectedUser, changePasswordUser)
	}
	if changePasswordPassword == "" {
		t.Error("Expected non-empty new password")
	}
	if changePasswordPassword != newConfig["password"] {
		t.Errorf("Expected new password '%s' to match the password in the returned config '%s'", changePasswordPassword, newConfig["password"])
	}
}

func TestRotateRootCredentialsWithDbError(t *testing.T) {
	errorMessage := "Aerospike error changing password"
	clientFactory := &MockClientFactory{
		OnChangePassword: func(user string, password string) error {
			return errors.New(errorMessage)
		},
	}
	plugin := initialisePlugin(t, clientFactory)

	_, err := plugin.RotateRootCredentials(context.Background(), []string{})

	if err == nil {
		t.Errorf("Expected error to be non nil")
	}
	if err.Error() != errorMessage {
		t.Errorf("Expected error '%s' but was '%s'", errorMessage, err.Error())
	}
}

func initialisePlugin(t *testing.T, clientFactory *MockClientFactory) dbplugin.Database {
	aerospike, err := plugin.New(clientFactory)
	if err != nil {
		t.Fatalf("Error creating Aerospike plugin: %s", err)
	}
	aerospikePlugin := aerospike.(dbplugin.Database)
	ctx := context.Background()
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": "test_admin_user",
		"password": "test_admin_password",
	}
	_, err = aerospikePlugin.Init(ctx, config, false)
	if err != nil {
		t.Fatalf("Error initialising Aerospike plugin: %s", err)
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
