import React, { useEffect, useState } from "react";
import { getDiagnostics } from "../hooks/api";
import type { GetDiagnosticsResponse } from "../types/gateon";
import { 
  IconActivity, 
  IconAlertTriangle, 
  IconCircleCheck, 
  IconGlobe, 
  IconShield, 
  IconServer, 
  IconRefresh,
  IconClock,
  IconExternalLink
} from "@tabler/icons-react";

const DiagnosticsPage: React.FC = () => {
  const [data, setData] = useState<GetDiagnosticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const res = await getDiagnostics();
      setData(res);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to fetch diagnostics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-64">
        <IconRefresh className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
        <h3 className="text-lg font-bold flex items-center">
          <IconAlertTriangle className="mr-2" /> Error
        </h3>
        <p>{error}</p>
        <button 
          onClick={fetchData}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Diagnostics & Connectivity</h1>
          <p className="text-slate-500">Troubleshoot TLS, connection, and Cloudflare issues.</p>
        </div>
        <button 
          onClick={fetchData}
          className="flex items-center px-4 py-2 bg-white border border-slate-200 rounded-lg shadow-sm hover:bg-slate-50 transition"
        >
          <IconRefresh className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* System Status Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white p-5 rounded-xl shadow-sm border border-slate-100">
          <div className="flex items-center text-slate-500 text-sm font-medium mb-3">
            <IconGlobe className="w-4 h-4 mr-2 text-blue-500" />
            Public IP Address
          </div>
          <div className="text-2xl font-mono font-bold text-slate-800">
            {data?.system.public_ip || "Unknown"}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Ensure your DNS/Cloudflare points to this IP.
          </p>
        </div>

        <div className="bg-white p-5 rounded-xl shadow-sm border border-slate-100">
          <div className="flex items-center text-slate-500 text-sm font-medium mb-3">
            <IconShield className="w-4 h-4 mr-2 text-orange-500" />
            Cloudflare Reachability
          </div>
          <div className="flex items-center">
            {data?.system.cloudflare_reachable ? (
              <>
                <IconCircleCheck className="w-6 h-6 text-emerald-500 mr-2" />
                <span className="text-2xl font-bold text-slate-800">Reachable</span>
              </>
            ) : (
              <>
                <IconAlertTriangle className="w-6 h-6 text-red-500 mr-2" />
                <span className="text-2xl font-bold text-slate-800">Unreachable</span>
              </>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Testing TCP connectivity to 1.1.1.1:53.
          </p>
        </div>

        <div className="bg-white p-5 rounded-xl shadow-sm border border-slate-100">
          <div className="flex items-center text-slate-500 text-sm font-medium mb-3">
            <IconActivity className="w-4 h-4 mr-2 text-purple-500" />
            Recent TLS Errors
          </div>
          <div className="text-2xl font-bold text-slate-800">
            {data?.recent_tls_errors.length || 0}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Handshake failures in the last buffer.
          </p>
        </div>
      </div>

      {/* Troubleshooting Tips for 521 */}
      <div className="bg-blue-50 border border-blue-100 rounded-xl p-5">
        <h3 className="text-blue-800 font-bold flex items-center mb-2">
          <IconAlertTriangle className="w-5 h-5 mr-2" /> Troubleshooting Cloudflare 521
        </h3>
        <ul className="text-sm text-blue-700 space-y-1 list-disc ml-5">
          <li>Verify your firewall allows incoming traffic from <a href="https://www.cloudflare.com/ips/" target="_blank" rel="noreferrer" className="underline font-medium">Cloudflare IP ranges</a>.</li>
          <li>Ensure Gateon is listening on the expected port (usually 443).</li>
          <li>Check "Full (strict)" mode requires a valid certificate (Origin CA or trusted) on Gateon.</li>
          <li>Look at "Recent TLS Errors" below for handshake issues or EOFs.</li>
        </ul>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Entrypoints List */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-100 overflow-hidden">
          <div className="p-4 border-b border-slate-100 bg-slate-50 flex items-center">
            <IconServer className="w-5 h-5 mr-2 text-slate-500" />
            <h2 className="font-bold text-slate-700">Entrypoint Status</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-slate-500 font-medium border-b border-slate-100">
                <tr>
                  <th className="px-4 py-2">ID</th>
                  <th className="px-4 py-2">Address</th>
                  <th className="px-4 py-2">Connections (Act/Tot)</th>
                  <th className="px-4 py-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data?.entrypoints.map(ep => (
                  <tr key={ep.id} className="hover:bg-slate-50 transition">
                    <td className="px-4 py-3 font-medium text-slate-700">{ep.id}</td>
                    <td className="px-4 py-3 text-slate-500 font-mono">{ep.address}</td>
                    <td className="px-4 py-3 text-slate-600">
                      <span className="font-bold">{ep.active_connections}</span> / {ep.total_connections}
                    </td>
                    <td className="px-4 py-3">
                      {ep.listening ? (
                        <span className="px-2 py-0.5 bg-emerald-100 text-emerald-700 rounded-full text-xs font-bold">Listening</span>
                      ) : (
                        <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-xs font-bold">Stopped</span>
                      )}
                      {ep.last_error && (
                        <div className="text-[10px] text-red-500 mt-1 truncate max-w-[150px]" title={ep.last_error}>
                          {ep.last_error}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent TLS Errors */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-100 overflow-hidden">
          <div className="p-4 border-b border-slate-100 bg-slate-50 flex items-center">
            <IconShield className="w-5 h-5 mr-2 text-slate-500" />
            <h2 className="font-bold text-slate-700">Recent TLS Handshake Errors</h2>
          </div>
          <div className="p-0">
            {data?.recent_tls_errors.length === 0 ? (
              <div className="p-10 text-center text-slate-400">
                <IconCircleCheck className="w-10 h-10 mx-auto mb-2 text-emerald-200" />
                No recent TLS errors detected.
              </div>
            ) : (
              <div className="max-h-[400px] overflow-y-auto">
                <ul className="divide-y divide-slate-100">
                  {data?.recent_tls_errors.map((err, i) => (
                    <li key={i} className="p-4 hover:bg-slate-50 transition">
                      <div className="flex justify-between items-start mb-1">
                        <span className="text-xs font-bold text-slate-400 flex items-center font-mono">
                          <IconClock className="w-3 h-3 mr-1" />
                          {new Date(err.timestamp).toLocaleTimeString()}
                        </span>
                        <span className="px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-bold">
                          {err.entrypoint_id}
                        </span>
                      </div>
                      <div className="text-sm font-mono text-slate-700 break-all mb-1">
                        {err.remote_addr}
                      </div>
                      <div className="text-xs text-red-600 bg-red-50 p-2 rounded border border-red-100">
                        {err.error}
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DiagnosticsPage;
