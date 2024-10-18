package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/vsapronov/terraform-provider-mongodb2/mongodb"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: mongodb.Provider,
	})
}
