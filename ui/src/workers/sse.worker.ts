export function parseSSEMessage(data: string) {
  try {
    return JSON.parse(data);
  } catch (err) {
    throw new Error(`Failed to parse SSE message: ${(err as Error).message}`);
  }
}

self.onmessage = (e: MessageEvent) => {
  const { type, payload, id } = e.data;

  try {
    let result;
    switch (type) {
      case "parseSSE":
        result = parseSSEMessage(payload.data);
        break;
      default:
        throw new Error(`Unknown worker task type: ${type}`);
    }

    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: (error as Error).message });
  }
};
