# sealos-nm-agent

`sealos-nm-agent` collects traffic data and stores aggregated traffic records in MongoDB.

This project now provides two applications built from the same codebase:

- `sealos-nm-agent`: the main agent process
- `cleanup`: a standalone cleanup application intended to run as a Kubernetes `CronJob`

## Applications

### Agent

The agent is the long-running process that:

- watches traffic
- aggregates traffic records
- creates MongoDB collections when needed
- writes traffic data into MongoDB

### Cleanup

The cleanup application is a one-shot process that:

- connects to MongoDB
- checks whether cleanup is needed
- deletes expired traffic records from general collections
- exits after the cleanup run finishes

This application is intended to be scheduled externally, for example by Kubernetes `CronJob`.

## Collection mode

The traffic store supports two MongoDB collection modes:

- **time series collections**
- **general collections**

### Default behavior

By default, the agent automatically detects whether the target MongoDB deployment supports time series collections.

- If MongoDB supports time series collections, the agent will create and use time series collections.
- If MongoDB does not support time series collections, the agent will fall back to general collections.

You do not need to configure a mode explicitly for the common case.

### Force general collections

If you want to always use general collections, set:

```/dev/null/env.txt#L1-1
TS_FORCE_GENERAL_COLL=true
```

When this flag is enabled, the agent will not use time series collections even if MongoDB supports them.

## Retention and expiration

Traffic retention is controlled by:

```/dev/null/env.txt#L1-1
TS_DB_EXPIRE_AFTER=36h
```

How this value is used depends on the collection mode.

### When using time series collections

`TS_DB_EXPIRE_AFTER` is applied as the collection-level expiration window.

MongoDB handles expiration automatically.

### When using general collections

`TS_DB_EXPIRE_AFTER` is used by the cleanup application to determine which traffic records are expired.

Expired records are deleted by the standalone cleanup job.

## Cleanup CronJob

The cleanup application is designed to run separately from the agent.

A Kubernetes `CronJob` manifest is provided at:

```/dev/null/path.txt#L1-1
deploy/cleanup_cronjob.yaml
```

Use this when you are storing traffic in general collections.

### When cleanup is needed

Cleanup is needed when:

- `TS_FORCE_GENERAL_COLL=true`, or
- MongoDB does not support time series collections and the agent falls back to general collections

### When cleanup is not needed

Cleanup is not needed when:

- MongoDB supports time series collections, and
- `TS_FORCE_GENERAL_COLL` is not enabled

In that case, MongoDB handles expiration automatically through time series collection settings.

## Configuration summary

### Required database settings

```/dev/null/env.txt#L1-3
DB_ENABLED=true
DB_URI=<mongo-uri>
DB_NAME=<mongo-db-name>
```

### Traffic store settings

```/dev/null/env.txt#L1-5
TS_POD_TRAFFIC_COLL=traffic
TS_HOST_TRAFFIC_COLL=host_traffic
TS_DB_EXPIRE_AFTER=36h
TS_FORCE_GENERAL_COLL=false
TS_FLUSH_TIMEOUT=5s
```

## Deployment model

A typical Kubernetes deployment uses:

- a `DaemonSet` for the main agent
- a `CronJob` for cleanup

The provided manifests are:

```/dev/null/path.txt#L1-2
deploy/daemonset_deploy.yaml
deploy/cleanup_cronjob.yaml
```

## Image layout

The main container image contains two binaries:

```/dev/null/path.txt#L1-2
/app/sealos-nm-agent
/app/cleanup
```

The default image entrypoint runs the agent.

The cleanup `CronJob` overrides the command and runs:

```/dev/null/path.txt#L1-1
/app/cleanup
```

## Deprecated configuration

The old `TS_USE_TIME_SERIES_COLL` parameter is deprecated and no longer used.

Use automatic detection by default, or set `TS_FORCE_GENERAL_COLL=true` if you need to force general collections.