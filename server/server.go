package main

import (
	"net"

	"context"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "qkms/proto"
)

type qkmsRealServer struct {
	pb.UnimplementedQkmsServer
}

func (server *qkmsRealServer) ReadAccessKey(ctx context.Context, req *pb.ReadAccessKeyRequest) (*pb.ReadAccessKeyReply, error)
func (server *qkmsRealServer) GenerateAccessKey(ctx context.Context, req *pb.GenerateAccessKeyReply) (*pb.GenerateAccessKeyReply, error)
func (server *qkmsRealServer) CreateAccessKey(ctx context.Context, req *pb.CreateAccessKeyRequest) (*pb.CreateAccessKeyRequest, error)
func (server *qkmsRealServer) UpdateAccessKey(ctx context.Context, req *pb.UpdateAccessKeyRequest) (*pb.UpdateAccessKeyReply, error)
func (server *qkmsRealServer) RotateAccessKey(ctx context.Context, req *pb.RotateAccessKeyRequest) (*pb.RotateAccessKeyReply, error)
func (server *qkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *pb.GrantAccessKeyAuthorizationRequest) (*pb.GrantAccessKeyAuthorizationReply, error)

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
