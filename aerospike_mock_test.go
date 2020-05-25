package aerospike_test

import (
	plugin "github.com/G-Research/vault-plugin-database-aerospike"
	"github.com/aerospike/aerospike-client-go"
)

type MockClientFactory struct{}

func (*MockClientFactory) NewClientWithPolicyAndHost(clientPolicy *aerospike.ClientPolicy, hosts ...*aerospike.Host) (plugin.Client, error) {
	return &MockClient{}, nil
}

type MockClient struct{}

func (*MockClient) IsConnected() bool {
	return true
}

func (*MockClient) Close() {}

func (*MockClient) CreateUser(policy *aerospike.AdminPolicy, user string, password string, roles []string) error {
	return nil
}

func (*MockClient) DropUser(policy *aerospike.AdminPolicy, user string) error {
	return nil
}

func (*MockClient) ChangePassword(policy *aerospike.AdminPolicy, user string, password string) error {
	return nil
}
