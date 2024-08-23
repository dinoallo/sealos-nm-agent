package pod

import (
	"context"
	"strings"
)

type POD_TYPE int64

const (
	POD_TYPE_UNKNOWN POD_TYPE = iota
	POD_TYPE_DB
	POD_TYPE_APP
	POD_TYPE_TERMINAL
	POD_TYPE_JOB
	POD_TYPE_OTHER
	POD_TYPE_OBJECTSTORAGE

	CHECK_DB_LABEL_KEY       = "apps.kubeblocks.io/component-name"
	CHECK_TERMINAL_LABEL_KEY = "TerminalID"
	CHECK_APP_LABEL_KEY      = "app"
	CHECK_JOB_LABEL_KEY      = "job-name"
	DB_TYPE_LABEL_KEY        = "apps.kubernetes.io/instance"
	APP_TYPE_LABEL_KEY       = "app"
	JOB_TYPE_LABEL_KEY       = "job-name"
)

func GetPodTypeAndTypeName(ctx context.Context, labels map[string]string) (POD_TYPE, string) {
	var podType POD_TYPE = POD_TYPE_UNKNOWN
	var podTypeName string
	if dbID, isDB := labels[CHECK_DB_LABEL_KEY]; isDB && dbID != "" {
		podType = POD_TYPE_DB
		if name, exists := labels[DB_TYPE_LABEL_KEY]; exists {
			podTypeName = name
		}
	} else if tid, isTerm := labels[CHECK_TERMINAL_LABEL_KEY]; isTerm && tid != "" {
		podType = POD_TYPE_TERMINAL
	} else if aid, isApp := labels[CHECK_APP_LABEL_KEY]; isApp && aid != "" {
		podType = POD_TYPE_APP
		podTypeName = aid
	} else if jid, isJob := labels[CHECK_JOB_LABEL_KEY]; isJob && jid != "" {
		podType = POD_TYPE_JOB
		podTypeName = strings.SplitN(jid, "-", 2)[0]
	} else {
		podType = POD_TYPE_OTHER
	}
	return podType, podTypeName
}
