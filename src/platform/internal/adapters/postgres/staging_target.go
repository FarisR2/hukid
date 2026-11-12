package postgres

import (
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
)

// StagingDatabase is the only database name the "staging" profile accepts (ADR-0028).
const StagingDatabase = "hukid_staging"

// stagingTarget accepts a remote runtime database. There must be no connection
// fallbacks, so sslmode has to be explicit (the pgx default "prefer" adds a plaintext
// fallback and is rejected). Plaintext is allowed only toward a single-label name, such
// as a container-network alias; any other host (dotted name or IP literal) needs TLS.
func stagingTarget(config *pgx.ConnConfig) bool {
	if config.Database != StagingDatabase || len(config.Fallbacks) != 0 || config.Host == "" || strings.HasPrefix(config.Host, "/") {
		return false
	}
	if config.TLSConfig != nil {
		return true
	}
	return net.ParseIP(config.Host) == nil && !strings.Contains(config.Host, ".")
}
