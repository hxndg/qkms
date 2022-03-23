package qkms_logic

import (
	"context"
	pb "qkms/proto"
)

func (server *QkmsRealServer) ReadAccessKey(ctx context.Context, req *pb.ReadAccessKeyRequest) (*pb.ReadAccessKeyReply, error)
func (server *QkmsRealServer) GenerateAccessKey(ctx context.Context, req *pb.GenerateAccessKeyReply) (*pb.GenerateAccessKeyReply, error)
func (server *QkmsRealServer) CreateAccessKey(ctx context.Context, req *pb.CreateAccessKeyRequest) (*pb.CreateAccessKeyRequest, error)
func (server *QkmsRealServer) UpdateAccessKey(ctx context.Context, req *pb.UpdateAccessKeyRequest) (*pb.UpdateAccessKeyReply, error)
func (server *QkmsRealServer) RotateAccessKey(ctx context.Context, req *pb.RotateAccessKeyRequest) (*pb.RotateAccessKeyReply, error)
func (server *QkmsRealServer) GrantAccessKeyAuthorization(ctx context.Context, req *pb.GrantAccessKeyAuthorizationRequest) (*pb.GrantAccessKeyAuthorizationReply, error)
