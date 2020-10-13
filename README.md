# vault-plugin-database-aerospike

A [Vault](https://www.vaultproject.io) plugin for [Aerospike](https://www.aerospike.com).

This project uses the database plugin interface introduced in Vault version 0.7.1.

## Build

Pre-built binaries for Linux, macOS and Windows can be found at [the releases page](https://github.com/aerospike-community/vault-plugin-database-aerospike/releases).

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
Success! Data written to: sys/plugins/catalog/database/aerospike-database-plugin

$ vault secrets enable database
Success! Enabled the database secrets engine at: database/

# host follows the same convention used by the Aerospike command line tools (asadm, asinfo, ...)
# The syntax is "<host1>[:<tlsname1>][:<port1>],..."
$ vault write database/config/aerospike \
    plugin_name=aerospike-database-plugin \
    allowed_roles="*" \
    host=url.to.aerospike.db:3443 \
    username='vaultadmin' \
    password='reallysecurepassword'

# You should consider rotating the admin password.
# Note that if you do, the new password will never be made available through Vault,
# so you should create a vault-specific database admin user for this.
$ vault write -force database/rotate-root/aerospike
Success! Data written to: database/rotate-root/aerospike
```

If running the plugin on macOS you may run into an issue where the OS prevents it from being executed.
See [How to open an app that hasn't been notarized or is from an unidentified developer](https://support.apple.com/en-us/HT202491) on Apple's support website to be able to run this.

## Usage

### Statements

The [creation statements](https://www.vaultproject.io/api/secret/databases/index.html#creation_statements) are defined as a JSON blob that has a an array of roles.

JSON example:
```json
{ "roles": ["read", "user-admin"] }
```

### Roles

#### Dynamic role

Sample commands for creating a dynamic role and generating credentials for it:

```sh
$ vault write database/roles/as-reader \
    db_name=aerospike \
    creation_statements='{"roles":["read"]}' \
    default_ttl=1h \
    max_ttl=24h
Success! Data written to: database/roles/as-reader

$ vault read database/creds/as-reader
Key                Value
---                -----
lease_id           database/creds/as-reader/sCKFOMxr3bKx0MSyV2O9vOIt
lease_duration     1h
lease_renewable    true
password           A1a-IMCI3TGEyZWDmiyn
username           v-token-as-reader-yYbN28OzeWbw1e4r5Ayr-1602523665
```

#### Static role

Sample commands for creating a static role and reading its current credentials (the user needs to already exist in Aerospike):

```sh
$ vault write database/static-roles/as-rwuser \
    db_name=aerospike \
    username=rwuser \
    rotation_period=1h
Success! Data written to: database/static-roles/as-rwuser

$ vault read database/static-creds/as-rwuser
Key                    Value
---                    -----
last_vault_rotation    2020-10-12T18:03:01.4751843Z
password               A1a-tZqNXpivBu6dfATJ
rotation_period        1h
ttl                    59m45s
username               rwuser
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
