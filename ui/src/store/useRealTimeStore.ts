import { create } from 'zustand';
import { getApiUrl } from '../hooks/api';
import type { Anomaly, AuditLog } from '../types/gateon';

type EventType = 'audit' | 'threat';

interface RealTimeEvent {
  type: EventType;
  data: any;
}

interface RealTimeState {
  isConnected: boolean;
  connect: () => void;
  disconnect: () => void;
  subscribers: Map<EventType, Set<(data: any) => void>>;
  subscribe: (type: EventType, callback: (data: any) => void) => () => void;
}

let eventSource: EventSource | null = null;

export const useRealTimeStore = create<RealTimeState>((set, get) => ({
  isConnected: false,
  subscribers: new Map(),

  connect: () => {
    if (eventSource) return;

    const url = getApiUrl('/v1/watch');
    eventSource = new EventSource(url, { withCredentials: true });

    eventSource.onopen = () => {
      set({ isConnected: true });
    };

    eventSource.onmessage = (event) => {
      try {
        const ev = JSON.parse(event.data) as RealTimeEvent;
        const subs = get().subscribers.get(ev.type);
        if (subs) {
          subs.forEach((cb) => cb(ev.data));
        }
      } catch (err) {
        console.error('Failed to parse multiplexed SSE event', err);
      }
    };

    eventSource.onerror = () => {
      set({ isConnected: false });
      eventSource?.close();
      eventSource = null;
      // Simple retry logic
      setTimeout(() => get().connect(), 5000);
    };
  },

  disconnect: () => {
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
    };
  },
}));
