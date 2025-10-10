<span align="center">

<a href="https://www.scrypted.app/"><img alt="scrypted" src="https://www.scrypted.app/img/logo.png" width="80px"></a>
<img alt="SimpliSafe Logo" src="https://raw.githubusercontent.com/homebridge-simplisafe3/homebridge-simplisafe3/master/.github/simplisafe_logo_wplus.png" width="380px" />

</span>

# Scrypted SimpliSafe Cameras

An unofficial [Scrypted](https://github.com/koush/scrypted) plugin that connects SimpliSafe indoor and doorbell cameras to your Scrypted server. The plugin handles OAuth authentication, discovers every camera on your account, and exposes live video, snapshots, and motion events to the rest of your smart home.

## Features
- Discovers SimpliSafe cameras and registers them as Scrypted camera devices automatically.
- Streams H.264 video (up to each camera's native resolution) with AAC audio suitable for HomeKit, Google Home, and other Scrypted integrations.
- Emits motion events in real time so you can trigger automations the moment a camera detects motion or a doorbell rings.
- Maintains OAuth refresh tokens on your behalf and recovers gracefully from rate limits and transient API errors.
- Optional verbose logging and device cleanup tools to help with troubleshooting.

## Prerequisites
- A running Scrypted server (local or hosted) with permission to install custom plugins.
- A SimpliSafe account with at least one camera (SimpliCam or Video Doorbell Pro) and the ability to log in with two-factor authentication.
- Node.js 18+ if you plan to build or develop the plugin locally.

## Installation

### Via Scrypted UI
- Search for `@kylewhirl` and you'll see the scrypted-simplisafe plugin

### Via terminal
1. **Install dependencies**
   ```bash
   npm install
   ```
2. **Build the plugin bundle**
   ```bash
   npm run build
   ```
3. **Deploy to your Scrypted server**
   - For one-off testing, run `npm run scrypted-deploy-debug` or `npm run scrypted-vscode-launch` to push the bundle to the Scrypted instance defined in `.vscode/settings.json`.
   - For production, run `npm run scrypted-deploy` to upload the compiled bundle.
4. Open the Scrypted Admin Console, enable the **SimpliSafe Cameras** plugin, and complete authentication (see below).

Once authenticated, the plugin will enumerate your cameras and create one Scrypted device per camera. Each device implements the `Camera`, `VideoCamera`, and `MotionSensor` interfaces.

## Authentication
SimpliSafe requires OAuth sign-in through their hosted login page. The flow mirrors the process documented by the [homebridge-simplisafe3](https://github.com/homebridge-simplisafe3/homebridge-simplisafe3) project and follows these steps:

1. In the Scrypted Admin Console, open **Plugins → SimpliSafe Cameras → Settings**.
2. Copy the **Login URL** value and open it in a desktop browser (Chrome works best).
3. Sign in with your SimpliSafe credentials and complete any email or two-factor prompts.
4. After approval, SimpliSafe tries to redirect to a custom URI such as `com.simplisafe.mobile://...`. Most browsers block the navigation:
   - In Chrome: press `Cmd+Option+J` / `Ctrl+Shift+J` to open DevTools, switch to the **Console**, and copy the full redirect URL from the error message.
   - Avoid Safari 15.1+—it hides the redirect URL entirely. Mobile browsers are also unsupported.
5. Paste the entire redirect URL (including `com.simplisafe.mobile://...`) into the **Authorization Redirect URL** field in the plugin settings and click **Save**.
6. The plugin exchanges the authorization code for tokens, stores the refresh token, and refreshes camera data. Watch the **Authentication Status** field for confirmation.

### Extra options
- **Refresh Token**: Paste a known-good refresh token if you performed the flow elsewhere. Leave blank to rely on the redirect URL flow.
- **Account Number**: Required only when your SimpliSafe login holds multiple monitoring plans. Enter the numeric account ID you want the plugin to use.
- **Debug Logging**: Toggle verbose logs while diagnosing issues.

If authentication fails, reset the **Authorization Redirect URL** field and repeat the steps above. The login URL can be reused; a fresh redirect URL is required for every attempt.

## Usage Notes
- Camera live streams offer multiple resolutions based on the SimpliSafe quality settings. Scrypted clients will automatically pick the best match.
- Motion events arrive via SimpliSafe's realtime websocket and map to the `MotionSensor` interface. Automations can filter on doorbell presses vs. motion using Scrypted scripting templates.
- The plugin caches camera metadata to survive short-term API outages. Toggle debug logging to review what the SimpliSafe API is returning.
- Set the environment variable `SIMPLISAFE_DEV_CLEAN=1` when running `npm run dev:logs` to remove stale Scrypted device entries created during development.

## Development
- `npm run scrypted-vscode-launch` – Build and deploy the plugin to the Scrypted host defined in `.vscode/settings.json`, then attach the VS Code debugger.
- `npm run dev:logs` – Continuously stream Scrypted logs for rapid troubleshooting (requires `SIMPLISAFE_DEV_CLEAN=1` to enable automatic cleanup).
- `npm run scrypted-debug` – Launch a debug session against the configured Scrypted instance without deploying.

### Project structure
- `src/main.ts` – Core plugin implementation: OAuth manager, API client, camera device classes, and realtime event handling.
- `src/types` – Type stubs for third-party libraries used during snapshot extraction.

Pull requests that improve stability, add new device types, or enhance logging are welcome. Please open an issue describing your use case before submitting significant changes.
