package cache

import "errors"

var (
	ErrTimeoutGettingExpiredEntries = errors.New("timeout while fetching the expired entries. you might not get a smaller batch")
)
