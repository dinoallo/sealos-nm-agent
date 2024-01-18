package main

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/agent/counter.proto
import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/bpf/bytecount"
	// 	"github.com/dinoallo/sealos-networkmanager-agent/exporter"
	"github.com/dinoallo/sealos-networkmanager-agent/server"
	"github.com/dinoallo/sealos-networkmanager-agent/store"

	"net"

	"go.uber.org/zap"

	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

const (
	// Port for gRPC server to listen to
	GRPC_SERVER_PORT = "0.0.0.0:50051"
	DB_NAME_ENV      = "DB_NAME"
	DB_URI_ENV       = "DB_URI"
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

	// Init Store
	cred := store.DBCred{
		DBURI: dbUri,
		DB:    dbName,
	}
	stm, err := store.NewStoreManager(cred, devLogger)
	if err != nil {
		log.Fatalf("unable to start the store: %v", err)
	}
	trStore, err := store.NewTrafficReportStore(devLogger)
	if err != nil {
		log.Fatalf("unable to create the store for traffic reports")
	} else {
		stm.RegisterStore(trStore)
	}
	if err != nil {
		log.Fatalf("unable to create the store for traffic accounts")
	} else {
		stm.RegisterStore(trStore)
	}
	cepStore, err := store.NewCiliumEndpointStore(devLogger)
	if err != nil {
		log.Fatalf("unable to crate the store for cilium endpoints")
	} else {
		stm.RegisterStore(cepStore)
	}
	if err := stm.Launch(ctx, 10); err != nil {
		log.Fatalf("unable to launch the store manager: %v", err)
	}
	// Init Factories
	bf, err := bytecount.NewFactory(devLogger, trStore, cepStore)
	if err != nil {
		log.Fatalf("unable to create the factory: %v", err)
	}

	if err := bf.Launch(ctx); err != nil {
		log.Fatalf("unable to launch the factory: %v", err)
	}

	/*
		bytecountExportChannel := make(chan *store.TrafficReport)
		bf.AddExportChannel(ctx, bytecountExportChannel)

		// Init Prom server
		if promExporter, err := exporter.NewExporter(devLogger, bytecountExportChannel); err != nil {
			log.Fatal(err)
			return
		} else {
			promExporter.Launch(ctx)
		} */

	// Init GRPC Server

	lis, err := net.Listen("tcp", GRPC_SERVER_PORT)

	if err != nil {
		log.Fatalf("failed connection: %v", err)
	}

	log.Infof("server listening at %v", lis.Addr())
	s := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
		}),
	)

	grpcServer, err := server.NewServer(devLogger, bf, cepStore)
	if err != nil {
		log.Fatalf("failed to create a new GRPC server: %v", err)
	}

	counterpb.RegisterCountingServiceServer(s, grpcServer)
	reflection.Register(s)
	go func() {
		<-sig
		cancel()
		s.GracefulStop()
		close(sig)
	}()

	if err := s.Serve(lis); err != nil {
		log.Infof("failed to serve: %v", err)
		return
	}

}
