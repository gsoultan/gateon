// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
// v2: the service descriptor lives beside the messages; protoc-gen-connect-es
// and its *_connect.ts output are retired.
import { ApiService } from "./gen/gateon/v1/api_pb";
import { useAuthStore } from "../store/useAuthStore";
import { getApiBaseUrl } from "../store/useApiConfigStore";

const transport = createConnectTransport({
  baseUrl: getApiBaseUrl() || window.location.origin,
  // Binary protobuf, not JSON.
  //
  // Connect-Web defaults to the JSON encoding, so these calls were sending and
  // parsing exactly what the hand-written REST layer sends — the whole reason
  // to speak Connect to a proto backend was switched off. connect-go accepts
  // both codecs on the same handler, so this is a client-side choice with no
  // server change behind it.
  //
  // What it buys: a smaller body than protojson (no field names on the wire,
  // varint numbers) and a parse that skips JSON entirely. Modest per call at
  // dashboard traffic, but free.
  useBinaryFormat: true,
  interceptors: [
    (next) => async (req) => {
      const token = useAuthStore.getState().token;
      if (token && token !== "__cookie__") {
        req.header.set("Authorization", `Bearer ${token}`);
      }
      return next(req);
    },
  ],
});

export const api = createClient(ApiService, transport);
