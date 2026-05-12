"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useApiConfigStore = void 0;
exports.getApiBaseUrl = getApiBaseUrl;
var zustand_1 = require("zustand");
var DEFAULT_API_URL = import.meta.env.VITE_API_URL || "";
var DEFAULT_REFRESH_INTERVAL = 10;
function loadFromStorage() {
    if (typeof localStorage === "undefined") {
        return { apiUrl: DEFAULT_API_URL, refreshInterval: DEFAULT_REFRESH_INTERVAL };
    }
    var savedUrl = localStorage.getItem("gateon_api_url");
    var savedInterval = localStorage.getItem("gateon_refresh_interval");
    var apiUrl = savedUrl !== null && savedUrl !== void 0 ? savedUrl : DEFAULT_API_URL;
    var parsed = savedInterval ? parseInt(savedInterval, 10) : DEFAULT_REFRESH_INTERVAL;
    var refreshInterval = Number.isFinite(parsed)
        ? Math.min(60, Math.max(1, parsed))
        : DEFAULT_REFRESH_INTERVAL;
    return { apiUrl: apiUrl, refreshInterval: refreshInterval };
}
exports.useApiConfigStore = (0, zustand_1.create)(function (set) { return (__assign(__assign({}, loadFromStorage()), { setApiConfig: function (apiUrl, refreshInterval) {
        if (typeof localStorage !== "undefined") {
            localStorage.setItem("gateon_api_url", apiUrl);
            localStorage.setItem("gateon_refresh_interval", String(Math.min(60, Math.max(1, refreshInterval))));
        }
        set({
            apiUrl: apiUrl,
            refreshInterval: Math.min(60, Math.max(1, refreshInterval)),
        });
    } })); });
/** Returns the API base URL for fetch/WebSocket (no trailing slash). */
function getApiBaseUrl() {
    var _a;
    var url = (_a = exports.useApiConfigStore.getState().apiUrl) !== null && _a !== void 0 ? _a : DEFAULT_API_URL;
    return url.replace(/\/$/, "");
}
