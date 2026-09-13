export async function listenOAuthCallbackServer(callbackServer) {
  await callbackServer.start();
  const listener = callbackServer.server;
  const address = listener?.address();
  if (!address || typeof address !== 'object' || !Number.isInteger(address.port)) {
    throw new Error('OAuth callback test server did not expose an active TCP listener');
  }
  return {
    server: listener,
    baseUrl: `http://127.0.0.1:${address.port}`,
    stop: () => callbackServer.stop()
  };
}
