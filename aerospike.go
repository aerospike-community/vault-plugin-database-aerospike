//Package aerospike implements a Vault database plugin for Aeropike.
package aerospike

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aerospike/aerospike-client-go"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
)

type aerospikeCreationStatement struct {
	Roles []string `json:"roles"`
}

const aerospikeTypeName = "aerospike"

var _ dbplugin.Database = &Aerospike{}

// Aerospike is an implementation of Database interface.
type Aerospike struct {
	*aerospikeConnectionProducer
	credsutil.CredentialsProducer
}

// New returns a new Aerospike instance.
func New(clientFactory ClientFactory) (interface{}, error) {
	db := new(clientFactory)
	// Wrap the plugin with middleware to sanitize errors
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func new(clientFactory ClientFactory) *Aerospike {
	connProducer := newConnectionProducer(clientFactory)
	connProducer.Type = aerospikeTypeName

	credsProducer := &credsutil.SQLCredentialsProducer{
		DisplayNameLen: 15,
		RoleNameLen:    15,
		// See https://www.aerospike.com/docs/guide/limitations.html
		UsernameLen: 63,
		Separator:   "-",
	}

	return &Aerospike{
		aerospikeConnectionProducer: connProducer,
		CredentialsProducer:         credsProducer,
	}
}

// Run instantiates an Aerospike object, and runs the RPC server for the plugin.
func Run(apiTLSConfig *api.TLSConfig) error {
	clientFactory := &aerospikeClientFactory{}
	dbType, err := New(clientFactory)
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database), api.VaultPluginTLSProvider(apiTLSConfig))

	return nil
}

// Type returns the TypeName for this backend
func (a *Aerospike) Type() (string, error) {
	return aerospikeTypeName, nil
}

func (a *Aerospike) getConnection(ctx context.Context) (Client, error) {
	client, err := a.Connection(ctx)
	if err != nil {
		return nil, err
	}

	return client.(Client), nil
}

// CreateUser generates the username/password on the underlying Aerospike
// secret backend as instructed by the CreationStatement provided. The creation
// statement is a JSON blob that has a an array of roles.
//
// JSON Example:
//  { roles": ["read", "user-admin"] }
func (a *Aerospike) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	// Grab the lock
	a.Lock()
	defer a.Unlock()

	statements = dbutil.StatementCompatibilityHelper(statements)

	if len(statements.Creation) == 0 {
		return "", "", dbutil.ErrEmptyCreationStatement
	}

	client, err := a.getConnection(ctx)
	if err != nil {
		return "", "", err
	}

	username, err = a.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", err
	}

	password, err = a.GeneratePassword()
	if err != nil {
		return "", "", err
	}

	// Unmarshal statements.CreationStatements into roles
	var cs aerospikeCreationStatement
	err = json.Unmarshal([]byte(statements.Creation[0]), &cs)
	if err != nil {
		return "", "", err
	}

	if len(cs.Roles) == 0 {
		return "", "", fmt.Errorf("roles array is required in creation statement")
	}

	if err := client.CreateUser(aerospike.NewAdminPolicy(), username, password, cs.Roles); err != nil {
		return "", "", err
	}

	return username, password, nil
}

// SetCredentials uses provided information to set/create a user in the
// database. Unlike CreateUser, this method requires a username be provided and
// uses the name given, instead of generating a name. This is used for creating
// and setting the password of static accounts, as well as rolling back
// passwords in the database in the event an updated database fails to save in
// Vault's storage.
func (a *Aerospike) SetCredentials(ctx context.Context, statements dbplugin.Statements, staticUser dbplugin.StaticUserConfig) (username, password string, err error) {
	// Grab the lock
	a.Lock()
	defer a.Unlock()

	client, err := a.getConnection(ctx)
	if err != nil {
		return "", "", err
	}

	username = staticUser.Username
	password = staticUser.Password

	if err := client.ChangePassword(aerospike.NewAdminPolicy(), username, password); err != nil {
		return "", "", err
	}

	return username, password, nil
}

// RenewUser is not supported on Aerospike, so this is a no-op.
func (a *Aerospike) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	// NOOP
	return nil
}

// RevokeUser drops the specified user.
func (a *Aerospike) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	// Grab the lock
	a.Lock()
	defer a.Unlock()

	client, err := a.getConnection(ctx)
	if err != nil {
		return err
	}

	return client.DropUser(aerospike.NewAdminPolicy(), username)
}

// RotateRootCredentials rotates the initial root database credentials. The new
// root password will only be known by Vault.
func (a *Aerospike) RotateRootCredentials(ctx context.Context, statements []string) (map[string]interface{}, error) {
	// Grab the lock
	a.Lock()
	defer a.Unlock()

	if len(a.Username) == 0 || len(a.Password) == 0 {
		return nil, errors.New("username and password are required to rotate")
	}

	client, err := a.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	password, err := a.GeneratePassword()
	if err != nil {
		return nil, err
	}

	if err := client.ChangePassword(aerospike.NewAdminPolicy(), a.Username, password); err != nil {
		return nil, err
	}

	// Close the database connection to ensure no new connections come in
	//client.Close()

	a.RawConfig["password"] = password
	return a.RawConfig, nil
}

type Client interface {
	IsConnected() bool
	Close()
	CreateUser(policy *aerospike.AdminPolicy, user string, password string, roles []string) error
	DropUser(policy *aerospike.AdminPolicy, user string) error
	ChangePassword(policy *aerospike.AdminPolicy, user string, password string) error
}

type ClientFactory interface {
	NewClientWithPolicyAndHost(clientPolicy *aerospike.ClientPolicy, hosts ...*aerospike.Host) (Client, error)
}

type aerospikeClientFactory struct{}

func (aerospikeClientFactory) NewClientWithPolicyAndHost(clientPolicy *aerospike.ClientPolicy, hosts ...*aerospike.Host) (Client, error) {
	return aerospike.NewClientWithPolicyAndHost(clientPolicy, hosts...)
}
