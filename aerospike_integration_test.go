// +build integration

package aerospike_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	plugin "github.com/G-Research/vault-plugin-database-aerospike"
	"github.com/aerospike/aerospike-client-go"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
)

var testHost *aerospike.Host

var adminClient *aerospike.Client

func TestMain(m *testing.M) {
	hostName := flag.String("host", "localhost", "Aerospike host to connect to")
	hostPort := flag.Int("port", 3000, "Port to connect to")
	adminUsername := flag.String("username", "admin", "admin username for Aerospike database")
	adminPassword := flag.String("password", "admin", "admin password for Aerospike database")
	flag.Parse()

	// Set up package variables to be used in tests
	testHost = aerospike.NewHost(*hostName, *hostPort)

	clientPolicy := aerospike.NewClientPolicy()
	clientPolicy.User = *adminUsername
	clientPolicy.Password = *adminPassword

	client, err := aerospike.NewClientWithPolicyAndHost(clientPolicy, testHost)
	if err != nil {
		fmt.Printf("Error connecting to aerospike database as admin: %s\n", err)
		os.Exit(1)
	}
	adminClient = client

	// Run tests
	testStatus := m.Run()

	// Tidy up
	adminClient.Close()

	os.Exit(testStatus)
}

func TestInitWithVerification(t *testing.T) {
	vaultAdminUser, vaultAdminPassword := setupVaultAdmin(t)
	defer removeVaultAdmin(t, vaultAdminUser)

	aerospike, err := plugin.New()
	if err != nil {
		t.Fatalf("Error creating Aerospike plugin: %s", err)
	}
	aerospikePlugin := aerospike.(dbplugin.Database)
	ctx := context.Background()
	config := getPluginConfig(vaultAdminUser, vaultAdminPassword)

	_, err = aerospikePlugin.Init(ctx, config, true)

	if err != nil {
		t.Errorf("Error initialising Aerospike plugin: %s", err)
	}
}

func TestCreateUserIntegration(t *testing.T) {
	vaultAdminUser, vaultAdminPassword := setupVaultAdmin(t)
	defer removeVaultAdmin(t, vaultAdminUser)
	plugin := getInitialisedPlugin(t, vaultAdminUser, vaultAdminPassword)
	ctx := context.Background()

	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": ["read"] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	username, password, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)
	if err != nil {
		t.Fatalf("Error creating user: %s", err)
	}

	verifyUserCanConnect(t, username, password)
}

func TestSetCredentialsIntegration(t *testing.T) {
	vaultAdminUser, vaultAdminPassword := setupVaultAdmin(t)
	defer removeVaultAdmin(t, vaultAdminUser)
	plugin := getInitialisedPlugin(t, vaultAdminUser, vaultAdminPassword)
	ctx := context.Background()

	// Create user
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": ["read"] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	username, initialPassword, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)
	if err != nil {
		t.Fatalf("Error creating user: %s", err)
	}

	// Change password
	newPassword := "new_password"
	statements = dbplugin.Statements{}
	user := dbplugin.StaticUserConfig{
		Username: username,
		Password: newPassword,
	}

	_, _, err = plugin.SetCredentials(ctx, statements, user)
	if err != nil {
		t.Fatalf("Error setting user credentials: %s", err)
	}

	verifyUserCanConnect(t, username, newPassword)
	verifyUserCannotConnect(t, username, initialPassword)
}

func TestRevokeUserIntegration(t *testing.T) {
	vaultAdminUser, vaultAdminPassword := setupVaultAdmin(t)
	defer removeVaultAdmin(t, vaultAdminUser)
	plugin := getInitialisedPlugin(t, vaultAdminUser, vaultAdminPassword)
	ctx := context.Background()

	// Create user
	expiration := time.Date(2020, 5, 26, 0, 0, 0, 0, time.UTC)
	statements := dbplugin.Statements{
		Creation: []string{`{ "roles": ["read"] }`},
	}
	usernameConfig := dbplugin.UsernameConfig{}

	username, password, err := plugin.CreateUser(ctx, statements, usernameConfig, expiration)
	if err != nil {
		t.Fatalf("Error creating user: %s", err)
	}
	verifyUserCanConnect(t, username, password)

	// Revoke user
	statements = dbplugin.Statements{}
	if err = plugin.RevokeUser(ctx, statements, username); err != nil {
		t.Fatalf("Error revoking user: %s", err)
	}

	verifyUserCannotConnect(t, username, password)
}

func TestRotateRootCredentialsIntegration(t *testing.T) {
	vaultAdminUser, initialPassword := setupVaultAdmin(t)
	defer removeVaultAdmin(t, vaultAdminUser)
	plugin := getInitialisedPlugin(t, vaultAdminUser, initialPassword)
	ctx := context.Background()

	newConfig, err := plugin.RotateRootCredentials(ctx, []string{})
	if err != nil {
		t.Fatalf("Error rotating root credentials: %s", err)
	}
	newPassword := newConfig["password"].(string)

	// Verify admin user can connect with new password
	verifyUserCanConnect(t, vaultAdminUser, newPassword)
	verifyUserCannotConnect(t, vaultAdminUser, initialPassword)

	// Verify plugin can be re-initialised with the new config
	// after first closing the existing connection.
	if err = plugin.Close(); err != nil {
		t.Fatalf("Error closing plugin connection: %s", err)
	}
	_, err = plugin.Init(ctx, newConfig, true)
	if err != nil {
		t.Fatalf("Error initialising Aerospike plugin after credential rotation: %s", err)
	}
}

func setupVaultAdmin(t *testing.T) (string, string) {
	vaultAdminUser := "vault_admin"
	vaultAdminPassword := "super_secret"
	roles := []string{"user-admin"}
	if err := adminClient.CreateUser(aerospike.NewAdminPolicy(), vaultAdminUser, vaultAdminPassword, roles); err != nil {
		t.Fatalf("Error creating vault admin user: %s", err)
	}
	return vaultAdminUser, vaultAdminPassword
}

func removeVaultAdmin(t *testing.T, adminUser string) {
	if err := adminClient.DropUser(aerospike.NewAdminPolicy(), adminUser); err != nil {
		t.Errorf("Error dropping vault admin user: %s", err)
	}
}

func getInitialisedPlugin(t *testing.T, vaultAdminUser, vaultAdminPassword string) dbplugin.Database {
	aerospike, err := plugin.New()
	if err != nil {
		t.Fatalf("Error creating Aerospike plugin: %s", err)
	}
	aerospikePlugin := aerospike.(dbplugin.Database)
	ctx := context.Background()
	config := getPluginConfig(vaultAdminUser, vaultAdminPassword)

	_, err = aerospikePlugin.Init(ctx, config, false)
	if err != nil {
		t.Fatalf("Error initialising Aerospike plugin: %s", err)
	}
	return aerospikePlugin
}

func verifyUserCanConnect(t *testing.T, username, password string) {
	clientPolicy := aerospike.NewClientPolicy()
	clientPolicy.User = username
	clientPolicy.Password = password

	client, err := aerospike.NewClientWithPolicyAndHost(clientPolicy, testHost)
	if err != nil {
		t.Errorf("Could not connect as user %s with password %s: %s", username, password, err)
	} else {
		client.Close()
	}
}

func verifyUserCannotConnect(t *testing.T, username, password string) {
	clientPolicy := aerospike.NewClientPolicy()
	clientPolicy.User = username
	clientPolicy.Password = password

	client, err := aerospike.NewClientWithPolicyAndHost(clientPolicy, testHost)
	if err == nil {
		t.Errorf("Expected user to be invalid but could connect as user %s with password %s", username, password)
		client.Close()
	}
}

func getPluginConfig(vaultAdminUser, vaultAdminPassword string) map[string]interface{} {
	return map[string]interface{}{
		"host":     fmt.Sprintf("%s:%d", testHost.Name, testHost.Port),
		"username": vaultAdminUser,
		"password": vaultAdminPassword,
	}
}
