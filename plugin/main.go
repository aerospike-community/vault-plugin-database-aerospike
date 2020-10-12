package main

import (
	"log"
	"os"

	plugin "github.com/aerospike-community/vault-plugin-database-aerospike"
	"github.com/hashicorp/vault/api"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := plugin.Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
