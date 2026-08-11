// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  aggregateTrafficSamples,
  aggregateBandwidthSamples,
  filterTrafficSamplesByRange,
  buildHourlyTrafficData,
  buildTrafficByPortData,
  buildTrafficByPathData,
  buildTrafficByServiceData,
  buildHourlyBandwidthData,
  buildBandwidthSummaries,
  buildBandwidthByRouterData,
  buildBandwidthByServiceData,
} from "../utils/dashboard";

self.onmessage = (e: MessageEvent) => {
  const { type, payload, id } = e.data;

  try {
    let result;
    switch (type) {
      case "aggregateTraffic":
        result = aggregateTrafficSamples(
          payload.samples,
          payload.resolutionMinutes,
          payload.range
        );
        break;
      case "aggregateBandwidth":
        result = aggregateBandwidthSamples(
          payload.samples,
          payload.resolutionMinutes,
          payload.range
        );
        break;
      case "filterTraffic":
        result = filterTrafficSamplesByRange(payload.samples, payload.range);
        break;
      case "buildHourlyTraffic":
        result = buildHourlyTrafficData(
          payload.samples,
          payload.resolutionMinutes,
          payload.range
        );
        break;
      case "buildDashboardData":
        // Batch operation for dashboard
        const { samples, bandwidthSamples, pathStats, resolutionMinutes, range, routes, services } = payload;
        result = {
          hourlyTraffic: buildHourlyTrafficData(samples, resolutionMinutes, range),
          trafficByPort: buildTrafficByPortData(pathStats),
          trafficByPath: buildTrafficByPathData(pathStats),
          trafficByService: buildTrafficByServiceData(pathStats, routes, services),
          hourlyBandwidth: buildHourlyBandwidthData(bandwidthSamples, resolutionMinutes, range),
          bandwidthSummaries: buildBandwidthSummaries(bandwidthSamples),
          bandwidthByRouter: buildBandwidthByRouterData(bandwidthSamples, routes),
          bandwidthByService: buildBandwidthByServiceData(bandwidthSamples, routes, services),
        };
        break;
      default:
        throw new Error(`Unknown worker task type: ${type}`);
    }

    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: (error as Error).message });
  }
};
