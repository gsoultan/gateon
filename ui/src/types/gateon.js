"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Protocol = exports.EntryPointType = exports.ClamavInstallationMode = exports.HealthCheckType = exports.TlsClientCertSelectionStrategy = exports.ProxyProtocolVersion = void 0;
var ProxyProtocolVersion;
(function (ProxyProtocolVersion) {
    ProxyProtocolVersion[ProxyProtocolVersion["PROXY_PROTOCOL_VERSION_UNSPECIFIED"] = 0] = "PROXY_PROTOCOL_VERSION_UNSPECIFIED";
    ProxyProtocolVersion[ProxyProtocolVersion["PROXY_PROTOCOL_VERSION_V1"] = 1] = "PROXY_PROTOCOL_VERSION_V1";
    ProxyProtocolVersion[ProxyProtocolVersion["PROXY_PROTOCOL_VERSION_V2"] = 2] = "PROXY_PROTOCOL_VERSION_V2";
})(ProxyProtocolVersion || (exports.ProxyProtocolVersion = ProxyProtocolVersion = {}));
var TlsClientCertSelectionStrategy;
(function (TlsClientCertSelectionStrategy) {
    TlsClientCertSelectionStrategy[TlsClientCertSelectionStrategy["TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC"] = 0] = "TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC";
    TlsClientCertSelectionStrategy[TlsClientCertSelectionStrategy["TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST"] = 1] = "TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST";
    TlsClientCertSelectionStrategy[TlsClientCertSelectionStrategy["TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER"] = 2] = "TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER";
})(TlsClientCertSelectionStrategy || (exports.TlsClientCertSelectionStrategy = TlsClientCertSelectionStrategy = {}));
var HealthCheckType;
(function (HealthCheckType) {
    HealthCheckType[HealthCheckType["HEALTH_CHECK_TYPE_UNSPECIFIED"] = 0] = "HEALTH_CHECK_TYPE_UNSPECIFIED";
    HealthCheckType[HealthCheckType["HEALTH_CHECK_TYPE_HTTP"] = 1] = "HEALTH_CHECK_TYPE_HTTP";
    HealthCheckType[HealthCheckType["HEALTH_CHECK_TYPE_GRPC"] = 2] = "HEALTH_CHECK_TYPE_GRPC";
    HealthCheckType[HealthCheckType["HEALTH_CHECK_TYPE_TCP"] = 3] = "HEALTH_CHECK_TYPE_TCP";
    HealthCheckType[HealthCheckType["HEALTH_CHECK_TYPE_CUSTOM"] = 4] = "HEALTH_CHECK_TYPE_CUSTOM";
})(HealthCheckType || (exports.HealthCheckType = HealthCheckType = {}));
var ClamavInstallationMode;
(function (ClamavInstallationMode) {
    ClamavInstallationMode[ClamavInstallationMode["INSTALLATION_MODE_UNSPECIFIED"] = 0] = "INSTALLATION_MODE_UNSPECIFIED";
    ClamavInstallationMode[ClamavInstallationMode["INSTALLATION_MODE_LOCAL"] = 1] = "INSTALLATION_MODE_LOCAL";
    ClamavInstallationMode[ClamavInstallationMode["INSTALLATION_MODE_DOCKER"] = 2] = "INSTALLATION_MODE_DOCKER";
})(ClamavInstallationMode || (exports.ClamavInstallationMode = ClamavInstallationMode = {}));
var EntryPointType;
(function (EntryPointType) {
    EntryPointType[EntryPointType["HTTP"] = 0] = "HTTP";
    EntryPointType[EntryPointType["GRPC"] = 1] = "GRPC";
    EntryPointType[EntryPointType["TCP"] = 2] = "TCP";
    EntryPointType[EntryPointType["UDP"] = 3] = "UDP";
    EntryPointType[EntryPointType["HTTP2"] = 4] = "HTTP2";
    EntryPointType[EntryPointType["HTTP3"] = 5] = "HTTP3";
})(EntryPointType || (exports.EntryPointType = EntryPointType = {}));
var Protocol;
(function (Protocol) {
    Protocol[Protocol["TCP"] = 0] = "TCP";
    Protocol[Protocol["UDP"] = 1] = "UDP";
})(Protocol || (exports.Protocol = Protocol = {}));
