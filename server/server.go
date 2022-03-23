package main

import (
	"net"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "qkms/proto"
)

func main() {
	lis, err := net.Listen("tcp", "127.0.0.1:21157")
	if err != nil {
		glog.Error("Can't Create Server, %s", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterQkmsServer(grpcServer, &qkmsRealServer{})

	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		glog.Errorln("")
	}
}
