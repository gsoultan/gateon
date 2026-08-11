// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createPromiseClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { ApiService } from "./gen/gateon/v1/api_connect";
import { useAuthStore } from "../store/useAuthStore";
import { getApiBaseUrl } from "../store/useApiConfigStore";

const transport = createConnectTransport({
  baseUrl: getApiBaseUrl() || window.location.origin,
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

export const api = createPromiseClient(ApiService, transport);
