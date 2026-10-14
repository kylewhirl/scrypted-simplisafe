# Offline regression checks

Run `npm ci --ignore-scripts`, `npm test`, `npm run typecheck`, and `npm run build`.

The Node test suite transpiles the real TypeScript modules in a VM and appends test-only
exports for their internal seams. Production exports are unchanged. It uses the installed
LiveKit protobuf implementation and SDK runtime enums. Peer connections, WebSockets,
Scrypted host services, timers, FFmpeg processes, UDP sockets, and snapshot HTTP calls
are deterministic substitutes. No account, camera, credentials, deployment, or external
network access is used by the tests.

Coverage includes startup timeouts and early disconnects, consumer negotiation cleanup,
publication retries, viewer rollover and talk-back, camera disposal, intercom replacement
races, legacy SimpliCam/SS002 stream and snapshot requests, discovery interfaces, motion
and doorbell event identifiers/state, host backoff/auth refresh, H264 keyframes, and RTP
continuity.

These checks establish application behavior with synthetic metadata and signaling. They
do not establish real camera compatibility, TURN/ICE reachability, FFmpeg TLS trust on a
Scrypted installation, HomeKit playback/audio quality, or long-running hardware stability.
Older cameras and doorbells still need physical streaming/snapshot/event regression checks;
newer cameras need a session extending past token expiry with talk-back before and after
rollover, plus multi-viewer and disconnect/reconnect checks.
