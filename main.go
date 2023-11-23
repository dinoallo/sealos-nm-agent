package main

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/counter.proto
import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dinoallo/sealos-networkmanager-agent/bpf/bytecount"
	"github.com/dinoallo/sealos-networkmanager-agent/server"
	"github.com/dinoallo/sealos-networkmanager-agent/store"

	"go.uber.org/zap"
	"net"

	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

const (
	// Port for gRPC server to listen to
	GRPC_SERVER_PORT = "0.0.0.0:50051"
	DB_HOST_ENV      = "DB_HOST"
	DB_PORT_ENV      = "DB_PORT"
	DB_USER_ENV      = "DB_USER"
	DB_NAME_ENV      = "DB_NAME"
	DB_PASS_ENV      = "DB_PASS"
)

func main() {

	var dbHost string = os.Getenv(DB_HOST_ENV)
	var dbPort string = os.Getenv(DB_PORT_ENV)
	var dbName string = os.Getenv(DB_NAME_ENV)
	var dbUser string = os.Getenv(DB_USER_ENV)
	var dbPass string = os.Getenv(DB_PASS_ENV)

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
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Init Store
	cred := &store.DBCred{
		DBHost: dbHost,
		DBPort: dbPort,
		DBUser: dbUser,
		DBPass: dbPass,
		DB:     dbName,
	}
	store, err := store.NewStore(cred, devLogger)
	if err != nil {
		log.Fatalf("unable to start the store: %v", err)
		return
	}

	if err := store.Launch(ctx, 32); err != nil {
		log.Fatalf("unable to launch the store: %v", err)
		return
	}

	// Init Factories

	bytecountFactory := &bytecount.Factory{Logger: devLogger, Store: store}

	if err := bytecountFactory.Launch(ctx); err != nil {
		log.Fatal(err)
		return
	}

	// Init GRPC Server

	lis, err := net.Listen("tcp", GRPC_SERVER_PORT)

	if err != nil {
		log.Fatalf("failed connection: %v", err)
		return
	}

	log.Infof("server listening at %v", lis.Addr())
	s := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
		}),
	)

	grpcServer, err := server.NewServer(devLogger, bytecountFactory)
	if err != nil {
		log.Fatalf("failed to create a new GRPC server: %v", err)
		return
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
