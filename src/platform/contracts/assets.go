// Package contracts embeds the single capability matrix used by runtime and tests.
package contracts

import _ "embed"

//go:embed capabilities.json
var Capabilities []byte
