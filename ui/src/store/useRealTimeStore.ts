import { create } from 'zustand';
import { getApiUrl } from '../hooks/api';
import type { Anomaly, AuditLog, MetricsSnapshot } from '../types/gateon';

type EventType = 'audit' | 'threat' | 'metrics';

interface RealTimeEvent {
  type: EventType;
  data: any;
}

interface RealTimeState {
  isConnected: boolean;
  lastMetrics: MetricsSnapshot | null;
  connect: () => void;
  disconnect: () => void;
  subscribers: Map<EventType, Set<(data: any) => void>>;
  subscribe: (type: EventType, callback: (data: any) => void) => () => void;
}

let eventSource: EventSource | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempt = 0;

/**
 * Delay before the next reconnect attempt.
 *
 * The stream used to retry every 5 seconds, forever. That is at its worst
 * exactly when it matters: a gateway under load drops the connection, and every
 * open dashboard tab starts knocking every 5 seconds until it recovers — adding
 * load to the thing that is already failing, on a host with two cores to share
 * between the dashboard and the proxy.
 *
 * Exponential to 30s, with jitter so that tabs opened together do not
 * synchronise into a herd that all reconnect on the same tick.
 */
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;

function reconnectDelay(attempt: number): number {
  const backoff = Math.min(RECONNECT_BASE_MS * 2 ** attempt, RECONNECT_MAX_MS);
  return backoff / 2 + Math.random() * (backoff / 2);
}

function clearReconnect() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

export const useRealTimeStore = create<RealTimeState>((set, get) => ({
  isConnected: false,
  lastMetrics: null,
  subscribers: new Map(),

  connect: () => {
    if (eventSource) return;
    clearReconnect();

    const url = getApiUrl('/v1/watch');
    eventSource = new EventSource(url, { withCredentials: true });

    eventSource.onopen = () => {
      // A connection that opened is the only evidence the backoff should reset.
      // Resetting on attempt instead would turn a flapping gateway back into a
      // fixed-interval retry.
      reconnectAttempt = 0;
      set({ isConnected: true });
    };

    eventSource.onmessage = (event) => {
      try {
        const ev = JSON.parse(event.data) as RealTimeEvent;
        if (ev.type === 'metrics') {
          set({ lastMetrics: ev.data });
        }
        const subs = get().subscribers.get(ev.type);
        if (subs) {
          subs.forEach((cb) => cb(ev.data));
        }
      } catch (err) {
        // Heartbeat is not JSON, so ignore parsing errors for it
        if (event.data?.includes('heartbeat')) return;
        console.error('Failed to parse multiplexed SSE event', err);
      }
    };

    eventSource.onerror = () => {
      set({ isConnected: false });
      eventSource?.close();
      eventSource = null;

      clearReconnect();
      const delay = reconnectDelay(reconnectAttempt);
      reconnectAttempt += 1;
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        get().connect();
      }, delay);
    };
  },

  disconnect: () => {
    // Cancels a pending reconnect as well as the open stream. Without this a
    // logout or teardown left a timer that reopened the connection moments
    // later, against a session that no longer existed.
    clearReconnect();
    reconnectAttempt = 0;
    eventSource?.close();
    eventSource = null;
    set({ isConnected: false });
  },

  subscribe: (type: EventType, callback: (data: any) => void) => {
    const { subscribers, connect } = get();
    
    if (!subscribers.has(type)) {
      subscribers.set(type, new Set());
    }
    subscribers.get(type)!.add(callback);
    
    // Ensure we are connected
    connect();

    return () => {
      const subs = get().subscribers.get(type);
      if (subs) {
        subs.delete(callback);
      }
      // The stream is deliberately left open when the last subscriber goes.
      // It is one connection for the whole app, and every navigation would
      // otherwise tear it down and immediately rebuild it — more work, and a
      // window during which pushed threats are missed. disconnect() is the
      // explicit way out, and logout uses it.
    };
  },
}));
