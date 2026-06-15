import { notifications } from "@mantine/notifications";
import { getApiErrorMessage } from "../hooks/useGateon";

type NotifyOptions = {
  title?: string;
  /** Override the resolved message (otherwise derived from the error). */
  message?: string;
};

/**
 * notifyError surfaces a consistent, human-readable error toast.
 * It resolves API/Error payloads via getApiErrorMessage so users never see
 * raw JSON or stack traces.
 */
export function notifyError(err: unknown, opts: NotifyOptions = {}): void {
  notifications.show({
    title: opts.title ?? "Something went wrong",
    message: opts.message ?? getApiErrorMessage(err),
    color: "red",
    withBorder: true,
  });
}

/** notifySuccess surfaces a consistent success toast. */
export function notifySuccess(message: string, title = "Success"): void {
  notifications.show({
    title,
    message,
    color: "green",
    withBorder: true,
  });
}
