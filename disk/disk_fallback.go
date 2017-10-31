// +build !darwin,!linux,!freebsd,!openbsd,!windows,!solaris

package disk

import "github.com/eoidc/gopsutil/internal/common"

func IOCounters(names ...string) (map[string]IOCountersStat, error) {
	return nil, common.ErrNotImplementedError
}

func Partitions(all bool) ([]PartitionStat, error) {
	return []PartitionStat{}, common.ErrNotImplementedError
}

func Usage(path string) (*UsageStat, error) {
	return nil, common.ErrNotImplementedError
}
