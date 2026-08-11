// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"log"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func main() {
	pasetoSecret := "12345678901234567890123456789012"
	databaseURL := "gateon_test.db"
	
	mgr, err := auth.NewManager(databaseURL, pasetoSecret, logger.Default())
	if err != nil {
		log.Fatalf("failed to init auth manager: %v", err)
	}
	defer mgr.Close()
	
	admin := &gateonv1.User{
		Username: "admin",
		Password: "password123",
		Role:     "admin",
	}
	
	if err := mgr.UpsertUser(admin); err != nil {
		log.Fatalf("failed to create admin: %v", err)
	}

	operator := &gateonv1.User{
		Username: "operator",
		Password: "password123",
		Role:     "operator",
	}
	if err := mgr.UpsertUser(operator); err != nil {
		log.Fatalf("failed to create operator: %v", err)
	}

	viewer := &gateonv1.User{
		Username: "viewer",
		Password: "password123",
		Role:     "viewer",
	}
	if err := mgr.UpsertUser(viewer); err != nil {
		log.Fatalf("failed to create viewer: %v", err)
	}

	log.Printf("Admin, operator, and viewer users created successfully in %s", databaseURL)
}
