import { Center, Loader } from "@mantine/core";

/**
 * RouteFallback is shown while a lazy route chunk is loading. It replaces the
 * previous blank (`null`) Suspense fallback so navigation no longer flashes an
 * empty screen.
 */
export function RouteFallback() {
  return (
    <Center mih="60vh" w="100%">
      <Loader type="bars" />
    </Center>
  );
}
