package util

import (
	"errors"
)

var (
	ErrBPFProgramNotLoaded      = errors.New("the bpf program was not loaded")
	ErrBPFProgramNotPinned      = errors.New("the bpf program was not pinned")
	ErrBPFMapFailedToCheck      = errors.New("failed to check if the bpf map exists")
	ErrBPFMapNotExist           = errors.New("the bpf map does not exist")
	ErrBPFMapAlreadyExists      = errors.New("the bpf map already exists")
	ErrBPFMapNotLoaded          = errors.New("the bpf map was not loaded")
	ErrBPFMapNotPinned          = errors.New("the bpf map was not pinned")
	ErrBPFMapNotUpdated         = errors.New("the bpf map was not updated")
	ErrBPFMapNotInitialized     = errors.New("the bpf map was not initialized")
	ErrBPFMapNotRemoved         = errors.New("the bpf map was not removed")
	ErrBPFCustomCallMapNotExist = errors.New("the bpf map for custom call does not exist")

	ErrUnknownDirection = errors.New("this direction type is not known")

	ErrParentLoggerNotInited = errors.New("the parent logger is not passed or not initialized")
	ErrLoggerNotInited       = errors.New("the logger is not initialized")

	// store
	ErrStoreNotInited               = errors.New("the store is not passed or not initialized")
	ErrCacheNotInited               = errors.New("the cache is not passed or not initialized")
	ErrStoreManagerNotInited        = errors.New("the store manager is not passed or not initialized")
	ErrCollectionAlreadyExists      = errors.New("the collection already exists")
	ErrPartialTTLIndexAlreadyExists = errors.New("the partial ttl index already exists")
	ErrConfigNotInited              = errors.New("the config is not passed or initialized")
	ErrParamNotInited               = errors.New("the param is not passed or initialized")
	ErrTRCollectionNotInited        = errors.New("the collection for traffic records is not initialized")
	ErrCEPCollectionNotInited       = errors.New("the collection for cilium endpoints is not initialized")

	// persistent
	ErrPersistentStorageNotInited = errors.New("the persistent storage is not passed or not initialized")
	ErrPersistentStorageNotReady  = errors.New("the persistent storage is not ready")

	// grpc
	ErrRequestNotPassed          = errors.New("the requests have not been passed")
	ErrServiceRegistrarNotInited = errors.New("the service registrar is not initialized or not passed")

	// factory
	ErrFactoryNotInited         = errors.New("the factory is not passed or not initialized")
	ErrBytecountFactoryNotReady = errors.New("the bytecount factory is not ready")

	// trafficreport
	ErrTrafficReportNotInited         = errors.New("the traffic report is nil or not initialized")
	ErrTimeoutWaitingForTrafficReport = errors.New("timeout waiting for any traffic reports")

	// trafficmonitor
	ErrTimeoutWaitingForTrafficMonitor = errors.New("timeout waiting for any traffic meters")
	ErrTrafficMonitorStoreNotReady     = errors.New("cilium endpoint store is not ready")

	// trafficrecord
	ErrTimeoutWaitingToAddTrafficRecord = errors.New("timeout waiting to add a traffic record")

	// cilium endpoint
	ErrCiliumEndpointStoreNotReady = errors.New("cilium endpoint store is not ready")
)
