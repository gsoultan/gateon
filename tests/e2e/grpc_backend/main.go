// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"net"
	"google.golang.org/grpc"
	"github.com/gsoultan/gateon/tests/e2e/testpb"
)

type server struct {
	testpb.UnimplementedTestServiceServer
}

func (s *server) Echo(ctx context.Context, in *testpb.EchoRequest) (*testpb.EchoResponse, error) {
	fmt.Printf("Received Echo: %s\n", in.GetMessage())
	return &testpb.EchoResponse{Message: "Echo: " + in.GetMessage()}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":8083")
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	testpb.RegisterTestServiceServer(s, &server{})
	fmt.Println("gRPC backend listening on :8083")
	if err := s.Serve(lis); err != nil {
		panic(err)
	}
}
