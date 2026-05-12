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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildQueryString = buildQueryStringInternal;
exports.getApiUrl = getApiUrl;
exports.apiFetch = apiFetch;
exports.getApiErrorMessage = getApiErrorMessage;
exports.restoreSessionFromCookie = restoreSessionFromCookie;
exports.setupGateon = setupGateon;
exports.testDbConnection = testDbConnection;
exports.getDiagnostics = getDiagnostics;
exports.applyRecommendation = applyRecommendation;
exports.removeMitigatedThreat = removeMitigatedThreat;
exports.getCloudflareIPs = getCloudflareIPs;
exports.traceRoute = traceRoute;
exports.installClamav = installClamav;
exports.runDeepScan = runDeepScan;
var useAuthStore_1 = require("../store/useAuthStore");
var useApiConfigStore_1 = require("../store/useApiConfigStore");
function buildQueryStringInternal(params) {
    if (!params)
        return "";
    var q = new URLSearchParams();
    if (params.page !== undefined)
        q.set("page", params.page.toString());
    if (params.page_size !== undefined)
        q.set("page_size", params.page_size.toString());
    if (params.search)
        q.set("search", params.search);
    var rp = params;
    if (rp.type)
        q.set("type", rp.type);
    if (rp.host)
        q.set("host", rp.host);
    if (rp.path)
        q.set("path", rp.path);
    if (rp.status)
        q.set("status", rp.status);
    var s = q.toString();
    return s ? "?".concat(s) : "";
}
function getApiUrl(path) {
    var base = (0, useApiConfigStore_1.getApiBaseUrl)();
    var token = useAuthStore_1.useAuthStore.getState().token;
    var url = new URL("".concat(base).concat(path), window.location.origin);
    if (token && token !== "__cookie__") {
        url.searchParams.set("token", token);
    }
    return url.toString();
}
function apiFetch(path_1) {
    return __awaiter(this, arguments, void 0, function (path, options) {
        var base, token, headers, res;
        if (options === void 0) { options = {}; }
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    base = (0, useApiConfigStore_1.getApiBaseUrl)();
                    token = useAuthStore_1.useAuthStore.getState().token;
                    headers = __assign({}, options.headers);
                    if (token && token !== "__cookie__") {
                        headers.Authorization = "Bearer ".concat(token);
                    }
                    return [4 /*yield*/, fetch("".concat(base).concat(path), __assign(__assign({}, options), { headers: headers, credentials: "include" }))];
                case 1:
                    res = _a.sent();
                    if (res.status === 401 && path !== "/v1/setup/required") {
                        useAuthStore_1.useAuthStore.getState().logout();
                    }
                    return [2 /*return*/, res];
            }
        });
    });
}
/** Returns a user-friendly message for API errors (e.g. 403 insufficient permissions). */
function getApiErrorMessage(err) {
    var raw = err instanceof Error ? err.message : String(err !== null && err !== void 0 ? err : "");
    try {
        var data = JSON.parse(raw);
        if ((data === null || data === void 0 ? void 0 : data.error) === "insufficient permissions" ||
            (data === null || data === void 0 ? void 0 : data.error) === "permission denied") {
            return "Insufficient permissions. You do not have access to perform this action.";
        }
        return (data === null || data === void 0 ? void 0 : data.error) || raw;
    }
    catch (_a) {
        return raw || "Request failed";
    }
}
/** Attempt to restore session from HttpOnly cookie (e.g. after refresh). */
function restoreSessionFromCookie() {
    return __awaiter(this, void 0, void 0, function () {
        var res, data, user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/me")];
                case 1:
                    res = _a.sent();
                    if (!res.ok)
                        return [2 /*return*/, false];
                    return [4 /*yield*/, res.json()];
                case 2:
                    data = _a.sent();
                    user = data === null || data === void 0 ? void 0 : data.user;
                    if ((user === null || user === void 0 ? void 0 : user.id) && (user === null || user === void 0 ? void 0 : user.username)) {
                        useAuthStore_1.useAuthStore.getState().setAuth("__cookie__", user);
                        return [2 /*return*/, true];
                    }
                    return [2 /*return*/, false];
            }
        });
    });
}
function setupGateon(req) {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/setup", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(req),
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function testDbConnection(payload) {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a, data;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/setup/test-db", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(payload),
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [4 /*yield*/, res.json()];
                case 4:
                    data = _b.sent();
                    return [2 /*return*/, !!(data === null || data === void 0 ? void 0 : data.success)];
            }
        });
    });
}
function getDiagnostics() {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/diagnostics")];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function applyRecommendation(anomalyType, source) {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/diagnostics/recommendation", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ anomaly_type: anomalyType, source: source }),
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function removeMitigatedThreat(source) {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/diagnostics/remove-mitigation", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ source: source }),
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function getCloudflareIPs() {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/cloudflare-ips")];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function traceRoute(ip) {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/diagnostics/traceroute", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ ip: ip }),
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function installClamav(req) {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/security/clamav/install", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(req),
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
function runDeepScan() {
    return __awaiter(this, void 0, void 0, function () {
        var res, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, apiFetch("/v1/security/clamav/scan", {
                        method: "POST",
                    })];
                case 1:
                    res = _b.sent();
                    if (!!res.ok) return [3 /*break*/, 3];
                    _a = Error.bind;
                    return [4 /*yield*/, res.text()];
                case 2: throw new (_a.apply(Error, [void 0, _b.sent()]))();
                case 3: return [2 /*return*/, res.json()];
            }
        });
    });
}
