package main

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/agent/counter.proto
import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/bpf/bytecount"
	"github.com/dinoallo/sealos-networkmanager-agent/service"

	"github.com/dinoallo/sealos-networkmanager-agent/store"

	"go.uber.org/zap"

	"golang.org/x/sync/errgroup"
)

type Component interface {
	GetName() string
	Launch(ctx context.Context, mainEg *errgroup.Group) error
	Stop(ctx context.Context) error
}

const (
	DB_NAME_ENV = "DB_NAME"
	DB_URI_ENV  = "DB_URI"
)

func main() {

	var dbName string = os.Getenv(DB_NAME_ENV)
	var dbUri string = os.Getenv(DB_URI_ENV)

	// Initialize the logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	devLogger := logger.Sugar()
	devLogger.Info("the logger for development is ready...")

	// Init logger for main
	log := devLogger.With(zap.String("component", "main"))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
	// Allow the current process to lock memory for eBPF resources.
	// only need this if the kernel version < 5.11
	// requires CAP_SYS_RESOURCE on kernel < 5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Init Stores
	cred := store.DBCred{
		DBURI: dbUri,
		DB:    dbName,
	}

	components := make(map[int]Component)
	var componentCount int = 0

	p := store.NewPersistent(cred)
	components[componentCount] = p
	componentCount++

	cepStore, err := store.NewCiliumEndpointStore(devLogger, p)
	if err != nil {
		log.Fatalf("unable to crate the store for cilium endpoints")
		return
	}
	components[componentCount] = cepStore
	componentCount++

	trStore, err := store.NewTrafficReportStore(devLogger, p)
	if err != nil {
		log.Fatalf("unable to crate the store for traffic reports")
		return
	}
	components[componentCount] = trStore
	componentCount++

	// Init Factories
	bf, err := bytecount.NewFactory(devLogger, trStore, cepStore)
	if err != nil {
		log.Fatalf("unable to create the factory: %v", err)
	}
	components[componentCount] = bf
	componentCount++

	// Init Services
	ts, err := service.NewTrafficService(devLogger, bf, cepStore)
	if err != nil {
		log.Fatalf("failed to create new traffic service: %v", err)
		return
	}
	components[componentCount] = ts
	componentCount++

	eg := &errgroup.Group{}
	for _, component := range components {
		name := component.GetName()
		if err := component.Launch(ctx, eg); err != nil {
			log.Fatalf("failed to launch component %v: %v", name, err)
			return
		}
		log.Infof("successfully launched component %v", name)
	}
	<-sig
	for _, component := range components {
		name := component.GetName()
		if err := component.Stop(ctx); err != nil {
			log.Fatalf("failed to stop component %v: %v", name, err)
			return
		}
		log.Infof("successfully stopped component %v", name)
	}
	close(sig)
}
