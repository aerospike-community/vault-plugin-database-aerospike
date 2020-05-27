# vault-plugin-database-aerospike

A [Vault](https://www.vaultproject.io) plugin for [Aerospike](https://www.aerospike.com)

This project uses the database plugin interface introduced in Vault version 0.7.1.

## Build

Pre-built binaries for Linux, macOS and Windows can be found at [the releases page](https://github.com/G-Research/vault-plugin-database-aerospike/releases).

For other platforms, there are not currently pre-built binaries available.

To build, `git clone` this repository and `go build -o vault-plugin-database-aerospike ./plugin` from the project directory.

## Installation

The Vault plugin system is documented on the [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the `vault-plugin-database-aerospike` executable downloaded/generated above in the directory.

Sample commands for registering and starting to use the plugin:

```sh
$ vault write sys/plugins/catalog/database/aerospike-database-plugin \
    sha256=$(openssl sha256 < vault-plugin-database-aerospike) \
    command="vault-plugin-database-aerospike"

$ vault secrets enable database

# host follows the same convention used by the Aerospike command line tools (asadm, asinfo, ...)
# The syntax is "<host1>[:<tlsname1>][:<port1>],..."
$ vault write database/config/aerospike \
    plugin_name=aerospike-database-plugin \
    allowed_roles="*" \
    host=url.to.aerospike.db:3443 \
    username='vaultadmin' \
    password='reallysecurepassword'

# You should consider rotating the admin password. Note that if you do, the new password will never be made available
# through Vault, so you should create a vault-specific database admin user for this.
$ vault write -force database/rotate-root/aerospike
```

If running the plugin on macOS you may run into an issue where the OS prevents it from being executed.
See [How to open an app that hasn't been notarized or is from an unidentified developer](https://support.apple.com/en-us/HT202491) on Apple's support website to be able to run this.

## Usage

### Statements

The [creation statements](https://www.vaultproject.io/api/secret/databases/index.html#creation_statements) are defined as a JSON blob that has a an array of roles.

JSON Example:
```json
{ "roles": ["read", "user-admin"] }
```

### TLS config

To enable TLS, you must set the `tls_ca` config parameter to a PEM representation of the CA that issued the Aerospike server certificate. If the name to use to validate the server certificate differs from the hostname used to access the server, you need to specify it in the `host` config parameter triplet.

TLS Example:
```sh
$ vault write database/config/aerospike \
    plugin_name=aerospike-database-plugin \
    allowed_roles="*" \
    host=url.to.aerospike.db:tls_server_name:3443 \
    tls_ca=$(cat rootCA.pem) \
    username='vaultadmin' \
    password='reallysecurepassword'
```

Mutual TLS is enabled by setting the `tls_certificate_key` config parameter to a PEM representation of the client certificate **and** the unencrypted private key.

Mutual TLS Example:
```sh
$ vault write database/config/aerospike \
    plugin_name=aerospike-database-plugin \
    allowed_roles="*" \
    host=url.to.aerospike.db:tls_server_name:3443 \
    tls_ca=$(cat rootCA.crt) \
    tls_certificate_key=$(cat client.crt client.key) \
    username='vaultadmin' \
    password='reallysecurepassword'
```

## Testing

Integration tests can be run against an Aerospike database running in Docker.
This requires a valid `features.conf` file to be present in the `test/aerospike_config` directory so that
security features of the Aerospike enterprise edition can be enabled.

Run the Aerospike server with:
```sh
docker-compose -f test/docker-compose.yml up
```

Then the integration tests can be run in a separate shell with:
```sh
go test -tags=integration
```

You can also run the tests against any Aerospike database by specifying the host and admin user credentials:
```sh
go test -tags=integration -host=localhost -port=3000 -username=admin -password=admin
```
