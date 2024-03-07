package service

import (
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/api/proto/agent"
)

func getResp(code counterpb.Code, msg string) *counterpb.CreateTrafficCounterResponse {
	return &counterpb.CreateTrafficCounterResponse{
		Status: &counterpb.Status{
			Code:    code,
			Message: msg,
		},
	}
}
