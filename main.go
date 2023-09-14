package main

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/counter.proto
import (
	"log"
	"net"

	bytecount "github.com/dinoallo/sealos-networkmanager-agent/bytecount"
	counterpb "github.com/dinoallo/sealos-networkmanager-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	// Port for gRPC server to listen to
	PORT = "0.0.0.0:50051"
)

func main() {
	lis, err := net.Listen("tcp", PORT)

	if err != nil {
		log.Fatalf("failed connection: %v", err)
	}

	s := grpc.NewServer()
	counterpb.RegisterCountingServiceServer(s, &bytecount.CountingServer{})
	reflection.Register(s)

	log.Printf("server listening at %v", lis.Addr())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
