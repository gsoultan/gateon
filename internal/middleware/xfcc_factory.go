// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

func (f *Factory) createXFCC(cfg map[string]string) (Middleware, error) {
	return XFCC(XFCCConfig{
		ForwardBy:      cfg["forward_by"] == "true",
		ForwardHash:    cfg["forward_hash"] == "true",
		ForwardSubject: cfg["forward_subject"] == "true",
		ForwardURI:     cfg["forward_uri"] == "true",
		ForwardDNS:     cfg["forward_dns"] == "true",
	}), nil
}
