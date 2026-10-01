package config

import (
	"github.com/spf13/pflag"
)

// CredentialPluginDir is where credential plugins listen, one <provider>.sock each.
var CredentialPluginDir = "/var/run/cluster-gateway/plugins"

func AddCredentialPluginFlags(set *pflag.FlagSet) {
	set.StringVarP(&CredentialPluginDir, "credential-plugin-dir", "", CredentialPluginDir,
		"the directory holding the unix sockets of credential plugins, used by clusters with the Provider credential type")
}
