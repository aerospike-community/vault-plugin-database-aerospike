package aerospike_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	plugin "github.com/G-Research/vault-plugin-database-aerospike"
	"github.com/aerospike/aerospike-client-go"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
)

func TestPluginInit(t *testing.T) {
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": "test_user",
		"password": "test_password",
	}
	clientCreated := false
	clientFactory := &MockClientFactory{
		OnNewClient: func(clientPolicy *aerospike.ClientPolicy, hosts ...*aerospike.Host) {
			clientCreated = true
		},
	}

	testPluginInitSuccess(t, config, clientFactory, false)

	if clientCreated {
		t.Fatal("Expected no client to have been created")
	}
}

func TestPluginInitWithVerify(t *testing.T) {
	username := "test_user"
	password := "test_password"
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": username,
		"password": password,
	}
	clientCreated := false
	createdClientUsername := ""
	createdClientPassword := ""
	clientFactory := &MockClientFactory{
		OnNewClient: func(clientPolicy *aerospike.ClientPolicy, hosts ...*aerospike.Host) {
			clientCreated = true
			createdClientUsername = clientPolicy.User
			createdClientPassword = clientPolicy.Password
		},
	}

	testPluginInitSuccess(t, config, clientFactory, true)

	if !clientCreated {
		t.Fatal("Expected client to have been created")
	}
	if createdClientUsername != username {
		t.Errorf("Expected client to be created with username '%s' but was '%s'", username, createdClientUsername)
	}
	if createdClientPassword != password {
		t.Errorf("Expected client to be created with password '%s' but was '%s'", password, createdClientPassword)
	}
}

func TestPluginInitWithTlsCa(t *testing.T) {
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": "test_user",
		"password": "test_password",
		"tls_ca":   testCaCert,
	}
	testPluginInitSuccess(t, config, &MockClientFactory{}, false)
}

func TestPluginInitWithTlsCaAndClientCert(t *testing.T) {
	config := map[string]interface{}{
		"host":                "test_host:3000",
		"username":            "test_user",
		"password":            "test_password",
		"tls_ca":              testCaCert,
		"tls_certificate_key": testClientCert + "\n" + testClientKey,
	}
	testPluginInitSuccess(t, config, &MockClientFactory{}, false)
}

func TestPluginInitHost(t *testing.T) {
	testCases := map[string]([]aerospike.Host){
		"test_host":               []aerospike.Host{{Name: "test_host", TLSName: "", Port: 3000}},
		"test_host:3000":          []aerospike.Host{{Name: "test_host", TLSName: "", Port: 3000}},
		"test_host:3123":          []aerospike.Host{{Name: "test_host", TLSName: "", Port: 3123}},
		"test_host:tls_name:3000": []aerospike.Host{{Name: "test_host", TLSName: "tls_name", Port: 3000}},
		"test_host_1,test_host_2": []aerospike.Host{{Name: "test_host_1", TLSName: "", Port: 3000}, {Name: "test_host_2", TLSName: "", Port: 3000}},
		"test_host_1:tls_name_1:3001,test_host_2:tls_name_2:3002": []aerospike.Host{
			{Name: "test_host_1", TLSName: "tls_name_1", Port: 3001},
			{Name: "test_host_2", TLSName: "tls_name_2", Port: 3002}},
	}
	for hostString, expectedHosts := range testCases {
		config := map[string]interface{}{
			"host":     hostString,
			"username": "test_user",
			"password": "test_password",
		}
		clientCreated := false
		clientHosts := []*aerospike.Host{}
		clientFactory := &MockClientFactory{
			OnNewClient: func(clientPolicy *aerospike.ClientPolicy, hosts ...*aerospike.Host) {
				clientCreated = true
				clientHosts = hosts
			},
		}

		testPluginInitSuccess(t, config, clientFactory, true)

		if !clientCreated {
			t.Errorf("Expected client to have been created for test case '%s'", hostString)
			continue
		}
		if len(clientHosts) != len(expectedHosts) {
			t.Errorf("Expected client to be created with %d hosts but got %d hosts for test case '%s'",
				len(expectedHosts), len(clientHosts), hostString)
			continue
		}
		for i, expectedHost := range expectedHosts {
			clientHost := clientHosts[i]
			if !(clientHost.Name == expectedHost.Name &&
				clientHost.TLSName == expectedHost.TLSName &&
				clientHost.Port == expectedHost.Port) {
				t.Errorf("Expected client %d to be created with host %s but got %s for test case '%s'",
					i, formatHost(&expectedHost), formatHost(clientHost), hostString)
			}
		}
	}
}

func TestPluginInitWithMissingHost(t *testing.T) {
	config := map[string]interface{}{
		"username": "test_user",
		"password": "test_password",
	}
	testPluginInitFailure(t, config, "host cannot be empty")
}

func TestPluginInitWithInvalidHost(t *testing.T) {
	config := map[string]interface{}{
		"host":     "a:b:c:d:e:f",
		"username": "test_user",
		"password": "test_password",
	}
	testPluginInitFailure(t, config, "too many components for host #1")
}

func TestPluginInitWithMissingUser(t *testing.T) {
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"password": "test_password",
	}
	testPluginInitFailure(t, config, "username cannot be empty")
}

func TestPluginInitWithMissingPassword(t *testing.T) {
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": "test_user",
	}
	testPluginInitFailure(t, config, "password cannot be empty")
}

func TestPluginInitWithInvalidCa(t *testing.T) {
	config := map[string]interface{}{
		"host":     "test_host:3000",
		"username": "test_user",
		"password": "test_password",
		"tls_ca":   "invalid_ca",
	}
	testPluginInitFailure(t, config, "failed to append CA to client policy")
}

func TestPluginInitWithInvalidClientKey(t *testing.T) {
	config := map[string]interface{}{
		"host":                "test_host:3000",
		"username":            "test_user",
		"password":            "test_password",
		"tls_ca":              testCaCert,
		"tls_certificate_key": "invalid certificate",
	}
	testPluginInitFailure(t, config, "unable to load tls_certificate_key_data")
}

func testPluginInitSuccess(t *testing.T, config map[string]interface{}, clientFactory *MockClientFactory, verify bool) {
	aerospike, err := plugin.New(clientFactory)
	if err != nil {
		t.Errorf("Error creating Aerospike plugin: %s", err)
	}
	aerospikePlugin := aerospike.(dbplugin.Database)
	ctx := context.Background()
	saveConfig, err := aerospikePlugin.Init(ctx, config, verify)
	if err != nil {
		t.Fatalf("Error initialising Aerospike plugin: %s", err)
	}
	if !reflect.DeepEqual(saveConfig, config) {
		t.Error("Expected config returned from Init to be the same as the passed config")
	}
}

func testPluginInitFailure(t *testing.T, config map[string]interface{}, expectedMessage string) {
	aerospike, err := plugin.New(&MockClientFactory{})
	if err != nil {
		t.Errorf("Error creating Aerospike plugin: %s", err)
	}
	aerospikePlugin := aerospike.(dbplugin.Database)
	ctx := context.Background()
	saveConfig, err := aerospikePlugin.Init(ctx, config, false)
	if saveConfig != nil {
		t.Error("Expected config returned from Init to be nil")
	}
	if err == nil {
		t.Errorf("Expected an error initialising the Aerospike plugin but there was none")
	} else if !strings.Contains(err.Error(), expectedMessage) {
		t.Errorf("Expected an error message containing '%s' but got '%s'", expectedMessage, err.Error())
	}
}

func formatHost(host *aerospike.Host) string {
	return fmt.Sprintf("%s:%s:%d", host.Name, host.TLSName, host.Port)
}

const testCaCert = `-----BEGIN CERTIFICATE-----
MIIDpTCCAo2gAwIBAgIUF03ujP2/J5PBmNVsNWLhtiJ5SQgwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCVUsxDzANBgNVBAcMBkxvbmRvbjETMBEGA1UECgwKRy1S
ZXNlYXJjaDEtMCsGA1UEAwwkdmF1bHQtcGx1Z2luLWRhdGFiYXNlLWFlcm9zcGlr
ZS10ZXN0MB4XDTIwMDUyNTIxNDQyNVoXDTI1MDUyNDIxNDQyNVowYjELMAkGA1UE
BhMCVUsxDzANBgNVBAcMBkxvbmRvbjETMBEGA1UECgwKRy1SZXNlYXJjaDEtMCsG
A1UEAwwkdmF1bHQtcGx1Z2luLWRhdGFiYXNlLWFlcm9zcGlrZS10ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ToBUNQnikpD1e/5KI2R7mmwVrAT
qs6gtA81mO/2LNAjyzAHmUR/gkB4koXiPhHvqIHXqRrs4XlaIwUmC+V9f4Mn7LA5
Dlbo99AwSwreI17xIqG2SCQ8Wob7KSnTAKNlD5eTWJYrSgU11BVOZCMPB/yOppF7
NF8mRaLyEYHPpO3AFIn6wmBkoxJYD0svu9pO9T9MpKHGdXIZUrm6pES5py7AaQxS
eSf7VFCGzIZK5MeLp8OQAK7Cye8SRkP9UZ2bYhWgeQj6MCOebm5vY1Mm3u5WNIVU
PcF4nYmn1NG1LICbAwg8QPeKLJq4CBTGnj9Q2DYjCRdi4jn4dDHu3ceJ0wIDAQAB
o1MwUTAdBgNVHQ4EFgQUOVPuBFp/AzWzHVEWfA1AsFloSfUwHwYDVR0jBBgwFoAU
OVPuBFp/AzWzHVEWfA1AsFloSfUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEASvuVXRzcoHJUZ1/BWrt8RgS88mh6ONWxoDikBoyZWv/5RRiMSjje
2dgz5wUhJdI9A7Apdxz8WG+LVY/rfQJaKnbdke3tZyyV5M/Gon+E5hsicIoCaIDM
S6rCi4E70IsmWbpRo1EbZ1a1ecfs/G7qF3J9IpRQCv10xZRGvRmFMT/t2AmltX/1
Aa9HIYiOAmrxwWQcyKIJYJg5/f4Kx76XXO8uusEAyWNTwzvKy/87ILTk1ac39msf
ynxZb3OJv6omPDxpDVnUEpbeau8SQtBZnltOgUT3i9gi+JOJ6eRyPRbPcQMEjU6v
sxJ9MaxS48ySpHPPdfRIpoDDxKAx2yuA3A==
-----END CERTIFICATE-----`

const testClientCert = `-----BEGIN CERTIFICATE-----
MIIEODCCAyACAQEwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVUsxDzANBgNV
BAcMBkxvbmRvbjETMBEGA1UECgwKRy1SZXNlYXJjaDEtMCsGA1UEAwwkdmF1bHQt
cGx1Z2luLWRhdGFiYXNlLWFlcm9zcGlrZS10ZXN0MB4XDTIwMDUyNTIyMDg0NFoX
DTMwMDUyMzIyMDg0NFowYjELMAkGA1UEBhMCVUsxDzANBgNVBAcMBkxvbmRvbjET
MBEGA1UECgwKRy1SZXNlYXJjaDEtMCsGA1UEAwwkdmF1bHQtcGx1Z2luLWRhdGFi
YXNlLWFlcm9zcGlrZS10ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA0GmyRI9T4YTXZ/9DNNuDh1lqYpXxiuoIzljevQsWMx1wf/l4OGfoHHCvo22v
th4/Si0vREz9pFfCOuXtA7ZNCef2bjKlGTh5hi8Bm7d431J1VAj0l/qbWOYwcACh
4qIm9PTQ5OTko+8MXSqpzY4YCeX9aKKC4JCJJh4C6mxl6BhLbAQj7GsbHEnWSkXR
pyeiKqGszy9E78HKDiMA/Trf3A5V5rhH4y0kyNhNVZhAdj7lDkv4RFh63zrYcYWx
9J0nQOT2p0FWLVZsfpzyyx0S3sMqWzqVGkKk+r2tAzDBrm2vKEkfhqFYhPOp07bR
6HD1Llnk6gyKdjCqn7tYLQhjRoLtoumkZUGegVikNZteS7sDv/MmbrunUAM2K6wi
prNz9dmThMzFvgJM3X7dJmpOfenecoOryAKE0SZTS1HvZi5mleqOApcCKNy3XwO0
3YczrZPYjf0hlAr/2g9WQd6Hv/kLxKJgAYH0lSIm7dXdx8GSwIZZoyFNhTP9T/iM
1R0PZYTJP+hY2gktzicHN4/t5m79yzzr401P5YteJUomZWvrceN0HtFf+Ly+dLx0
u/eFrY5/6g58/g9qGhoA3plBIpNk3Rnp3ZPAwJmMdBxHTViPQWD/jfCeahxhbapJ
qmDRLw8wI1rBBNeFitu9gY9JgyWoz7u5Fji98ymGTh8k6cECAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAvvi6xpzEA7eZcsW6vxM1M2jL/9ZCIVwLjWbtY3zcw+9cjw9P
kvMwCmOLdeNREIymbXEoXIEwobKsJx5TDzRKWm9bPXuV15XL2DFK0A2D8L5mI1wH
mXnfgG+1AdusB17SV06ubslJ88Kk+xeELCtZ0rUGCgRpW0XbKxYzRARw5GAAxNow
EPxGfCVELBvCWqosdYtP79rxZeKSvap4Pra19fXFNz6abwJktcym878CtizLDORb
b+zjgmwd0VhWKCJtW1ODy/1ZhzHXxBKmaVzWCxC/IQMoMgeEiosDBkNuMJVrDkk9
9vZ5QdNwX+9XY0pozb6iOaixXTiKH+8AGkaPRg==
-----END CERTIFICATE-----`

const testClientKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
