package buildinfo

import "fmt"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func String() string {
	return fmt.Sprintf("version=%s commit=%s build_date=%s", Version, Commit, BuildDate)
}
