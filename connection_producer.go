package aerospike

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/aerospike/aerospike-client-go/v5"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
)

// aerospikeConnectionProducer implements ConnectionProducer and provides an
// interface for databases to make connections.
type aerospikeConnectionProducer struct {
	Host string `json:"host" structs:"host" mapstructure:"host"`

	Username string `json:"username" structs:"username" mapstructure:"username"`
	Password string `json:"password" structs:"password" mapstructure:"password"`

	TLSCertificateKeyData []byte `json:"tls_certificate_key" structs:"-" mapstructure:"tls_certificate_key"`
	TLSCAData             []byte `json:"tls_ca"              structs:"-" mapstructure:"tls_ca"`

	Initialized  bool
	RawConfig    map[string]interface{}
	Type         string
	hosts        []*aerospike.Host
	clientPolicy *aerospike.ClientPolicy
	client       *aerospike.Client
	sync.Mutex
}

func (c *aerospikeConnectionProducer) Initialize(ctx context.Context, conf map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, conf, verifyConnection)
	return err
}

// Initialize parses connection configuration.
func (c *aerospikeConnectionProducer) Init(ctx context.Context, conf map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	c.Lock()
	defer c.Unlock()

	c.RawConfig = conf

	err := mapstructure.WeakDecode(conf, c)
	if err != nil {
		return nil, err
	}

	if len(c.Host) == 0 {
		return nil, fmt.Errorf("host cannot be empty")
	}

	c.hosts, err = c.getHosts()
	if err != nil {
		return nil, err
	}

	if len(c.Username) == 0 {
		return nil, fmt.Errorf("username cannot be empty")
	}

	if len(c.Password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	c.clientPolicy = aerospike.NewClientPolicy()
	c.clientPolicy.User = c.Username
	c.clientPolicy.Password = c.Password

	c.clientPolicy.TlsConfig, err = c.getTLSConfig()
	if err != nil {
		return nil, err
	}

	// Set initialized to true at this point since all fields are set,
	// and the connection can be established at a later time.
	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			return nil, errwrap.Wrapf("error verifying connection: {{err}} : {{c}}", err)
		}

		if !c.client.IsConnected() {
			return nil, fmt.Errorf("error verifying connection: not connected")
		}
	}

	return conf, nil
}

// Connection creates or returns an existing a database connection. If the session fails
// on a ping check, the session will be closed and then re-created.
// This method does not lock the mutex and it is intended that this is the callers
// responsibility.
func (c *aerospikeConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	// If we already have a session, test it and return
	if c.client != nil {
		if c.client.IsConnected() {
			return c.client, nil
		}
		// If the ping was unsuccessful, close it and ignore errors as we'll be
		// reestablishing anyways
		c.client.Close()
	}

	var err error
	c.client, err = aerospike.NewClientWithPolicyAndHost(c.clientPolicy, c.hosts...)
	if err != nil {
		return nil, err
	}
	return c.client, nil
}

// Close attempts to close the connection.
func (c *aerospikeConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.client != nil {
		c.client.Close()
	}

	c.client = nil

	return nil
}

func (c *aerospikeConnectionProducer) secretValues() map[string]interface{} {
	return map[string]interface{}{
		c.Password: "[password]",
	}
}

// getHosts parses the Host string in a format compatible with the aerospike CLI tools
func (c *aerospikeConnectionProducer) getHosts() ([]*aerospike.Host, error) {
	hosts := []*aerospike.Host{}

	for i, h := range strings.Split(c.Host, ",") {
		components := strings.Split(h, ":")

		if len(components) > 3 {
			return nil, fmt.Errorf("too many components for host #%d", i+1)
		}

		name := components[0]
		port := 3000
		if len(components) > 1 {
			var err error
			port, err = strconv.Atoi(components[len(components)-1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number for host #%d: %w", i+1, err)
			}
		}

		host := aerospike.NewHost(name, port)

		if len(components) == 3 {
			host.TLSName = components[1]
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// getTLSConfig parses the TLSCAData and TLSCertificateKeyData byte slices and
// builds a tls.Config.
func (c *aerospikeConnectionProducer) getTLSConfig() (*tls.Config, error) {
	if len(c.TLSCAData) == 0 {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}

	ok := tlsConfig.RootCAs.AppendCertsFromPEM(c.TLSCAData)
	if !ok {
		return nil, fmt.Errorf("failed to append CA to client policy")
	}

	if len(c.TLSCertificateKeyData) > 0 {
		certificate, err := tls.X509KeyPair(c.TLSCertificateKeyData, c.TLSCertificateKeyData)
		if err != nil {
			return nil, fmt.Errorf("unable to load tls_certificate_key_data: %w", err)
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	}

	return tlsConfig, nil
}
