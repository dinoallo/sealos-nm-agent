module github.com/dinoallo/sealos-networkmanager-agent

go 1.21

require (
	github.com/cilium/ebpf v0.11.0
	github.com/dgraph-io/ristretto v0.1.1
	github.com/florianl/go-tc v0.4.3
	github.com/jsimonetti/rtnetlink v0.0.0-20211022192332-93da33804786
	github.com/mdlayher/netlink v1.7.2
	github.com/stretchr/testify v1.8.4
	go.mongodb.org/mongo-driver v1.13.1
	go.uber.org/zap v1.26.0
	golang.org/x/sync v0.5.0
	golang.org/x/sys v0.19.0
	google.golang.org/grpc v1.60.1
	google.golang.org/protobuf v1.31.0
)

replace github.com/dinoallo/sealos-networkmanager-k8s-api => ../nm-k8s-api

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/golang/glog v1.1.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	go.uber.org/goleak v1.2.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.16.0 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231002182017-d307bd883b97 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
