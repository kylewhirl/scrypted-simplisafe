/**
 * Portions of this file are adapted from homebridge-simplisafe3
 * (https://github.com/homebridge-simplisafe3)
 * Copyright (c) 2020–2025 homebridge-simplisafe3 contributors
 * Licensed under the MIT License.
 */

import sdk, {
    BinarySensor,
    Camera,
    Device,
    DeviceState,
    DeviceProvider,
    FFmpegInput,
    Intercom,
    MediaObject,
    MotionSensor,
    RequestMediaStreamOptions,
    RequestPictureOptions,
    ResponseMediaStreamOptions,
    ResponsePictureOptions,
    RTCSessionControl,
    RTCSignalingChannel,
    RTCSignalingSession,
    ScryptedDeviceBase,
    ScryptedDeviceType,
    ScryptedInterface,
    ScryptedMimeTypes,
    Setting,
    SettingValue,
    Settings,
    VideoCamera,
} from '@scrypted/sdk';
import { LiveKitCameraStream, LiveViewResponse } from './livekit';
import { RtpPacket } from '@koush/werift';
import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios';
import axiosRetry from 'axios-retry';
import { ChildProcess, spawn } from 'child_process';
import { EventEmitter } from 'events';
import crypto from 'crypto';
import dgram from 'dgram';
import jpegExtract from 'jpeg-extract';
import WebSocket, { RawData } from 'ws';
import packageJson from '../package.json';

const { deviceManager, mediaManager, systemManager } = sdk;

const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
const readinessRetryInterval = 30_000;

const SS_OAUTH_AUTH_URL = 'https://auth.simplisafe.com/authorize';
const SS_OAUTH_CLIENT_ID = '42aBZ5lYrVW12jfOuu3CQROitwxg9sN5';
const SS_OAUTH_AUTH0_CLIENT = 'eyJ2ZXJzaW9uIjoiMi4zLjIiLCJuYW1lIjoiQXV0aDAuc3dpZnQiLCJlbnYiOnsic3dpZnQiOiI1LngiLCJpT1MiOiIxNi4zIn19';
const SS_OAUTH_REDIRECT_URI = 'com.simplisafe.mobile://auth.simplisafe.com/ios/com.simplisafe.mobile/callback';
const SS_OAUTH_SCOPE = 'offline_access%20email%20openid%20https://api.simplisafe.com/scopes/user:platform';
const SS_OAUTH_AUDIENCE = 'https://api.simplisafe.com/';
const SS_OAUTH_DEVICE = 'iPhone';
const SS_OAUTH_DEVICE_UUID = '0000007E-0000-1000-8000-0026BB765291';

const subscriptionCacheTime = 3000;
const cameraCacheTime = 15000;
const rateLimitInitialInterval = 60_000;
// Keep the ceiling low. A blocked window suppresses every request to that host, so an overlong
// cap turns a brief upstream fault into an outage that outlives it — the camera would stay dark
// for hours after SimpliSafe recovered.
const rateLimitMaxInterval = 5 * 60 * 1000;
// SimpliSafe fronts app-hub.prd.aser.simplisafe.com with a Kong gateway that 403s requests whose
// User-Agent starts with a lowercase SDK token — `axios/1.10.0` and `okhttp/4.9.0` are both
// rejected, while `Axios/1.10.0`, `curl/8.4.0` and an absent UA all pass. Axios sets its own UA by
// default, so without this every getLiveView() call is refused and WebRTC streaming is dead while
// the rest of the plugin (api.simplisafe.com, which does not filter) keeps working. Do not remove;
// if this string ever needs to change, re-test it against /live-view first.
const SS_USER_AGENT = `scrypted-simplisafe/${packageJson.version}`;
// Media requests carry the SimpliSafe bearer token, so they must go to the hostname with TLS
// verification enabled — never to a resolved IP with verification disabled (MITM could steal the
// token, which grants full account access including the alarm).
const SS_MEDIA_HOST = 'media.simplisafe.com';
// Recording providers known to serve the SimpliSafe cloud FLV streaming endpoint.
// Add the value logged by SS:isUnsupported here once confirmed it works with the FLV path.
const SUPPORTED_RECORDING_PROVIDERS = new Set<string>(['simplisafe']);
const socketRetryInterval = 1000;
const socketHeartbeatInterval = 60_000;
const socketRetryBackoffCap = 60_000;
const RESOLUTION_INTERFACE: ScryptedInterface | string = (ScryptedInterface as any).Resolution ?? 'Resolution';

const ssOAuth: AxiosInstance = axios.create({
    baseURL: 'https://auth.simplisafe.com/oauth',
    headers: { 'User-Agent': SS_USER_AGENT },
});
axiosRetry(ssOAuth, { retries: 3 });

const AUTH_EVENTS = {
    REFRESH_CREDENTIALS_SUCCESS: 'REFRESH_CREDENTIALS_SUCCESS',
    REFRESH_CREDENTIALS_FAILURE: 'REFRESH_CREDENTIALS_FAILURE',
} as const;

const EVENT_TYPES = {
    CAMERA_MOTION: 'CAMERA_MOTION',
    DOORBELL: 'DOORBELL',
} as const;

class RateLimitError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'RateLimitError';
    }
}

interface SimplisafeCameraAdminSettings {
    fps?: number;
    bitRate?: number;
    firmwareVersion?: string;
}

interface SimplisafeCameraSettings {
    cameraName?: string;
    pictureQuality?: string;
    admin?: SimplisafeCameraAdminSettings;
}

interface SimplisafeCameraProviders {
    recording?: string;
    webrtc?: string;
    live?: string;
    allSupportedProviders?: {
        webrtc?: string[];
        recording?: string[];
        live?: string[];
    };
}

interface SimplisafeCameraSupportedFeatures {
    privacyShutter?: boolean;
    providers?: SimplisafeCameraProviders;
}

interface SimplisafeCameraDetails {
    uuid: string;
    name?: string;
    model?: string;
    status?: string;
    cameraSettings?: SimplisafeCameraSettings;
    supportedFeatures?: SimplisafeCameraSupportedFeatures;
    [key: string]: unknown;
}

type DebugProvider = () => boolean;

interface CachedCameraDescriptor {
    nativeId: string;
    name: string;
    type: ScryptedDeviceType;
    interfaces: (ScryptedInterface | string)[];
    info?: Device['info'];
}

interface SimplisafeRealtimeInternalDetails {
    mainCamera?: string;
    [key: string]: unknown;
}

interface SimplisafeRealtimeEvent {
    sid?: string;
    eventCid?: number;
    sensorSerial?: string;
    cameraSerial?: string;
    serial?: string;
    deviceSerial?: string;
    cameraUuid?: string;
    uuid?: string;
    detectedAt?: string | number;
    timestamp?: string | number;
    internal?: SimplisafeRealtimeInternalDetails;
    [key: string]: unknown;
}

interface SimplisafeRealtimeMessage {
    source?: string;
    type?: string;
    data?: SimplisafeRealtimeEvent;
    [key: string]: unknown;
}

/**
 * Newer SimpliSafe cameras stream over LiveKit (WebRTC) instead of the legacy FLV endpoint.
 * SimpliSafe labels them with providers.webrtc === 'kvs' (typically with live === 'none'), but the
 * live-view endpoint actually returns LiveKit connection details, not Amazon KVS.
 */
function isLiveKitCameraDetails(details: SimplisafeCameraDetails): boolean {
    const providers = details.supportedFeatures?.providers;
    return providers?.webrtc === 'kvs' || providers?.recording === 'kvs';
}

function normalizeIdSegment(value: string): string {
    return value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
}

function deriveCameraNativeId(camera: SimplisafeCameraDetails): string {
    const candidates: (string | undefined)[] = [
        (camera as any)?.serialNumber,
        (camera as any)?.serial,
        (camera as any)?.deviceSerial,
        (camera as any)?.macAddress,
        (camera as any)?.mac,
        camera.cameraSettings?.cameraName,
        camera.name,
        camera.uuid,
    ].map(candidate => (typeof candidate === 'string' ? candidate.trim() : undefined));

    const firstValid = candidates.find(candidate => candidate);
    const normalized = firstValid ? normalizeIdSegment(firstValid) : undefined;

    if (normalized) {
        return `simplisafe-camera-${normalized}`;
    }

    const fallback = camera.uuid
        ? normalizeIdSegment(camera.uuid)
        : crypto.createHash('sha1').update(JSON.stringify(camera)).digest('hex').slice(0, 10);
    return `simplisafe-camera-${fallback || 'unknown'}`;
}

function buildPlaceholderCameraDetails(
    nativeId: string,
    existing?: SimplisafeCameraDetails,
    preferredName?: string,
    fallbackUuid?: string,
): SimplisafeCameraDetails {
    const placeholderName = preferredName
        || existing?.cameraSettings?.cameraName
        || existing?.name
        || `Camera ${nativeId}`;
    const admin = existing?.cameraSettings?.admin;
    const uuid = existing?.uuid || fallbackUuid || nativeId;

    return {
        uuid,
        name: placeholderName,
        status: existing?.status ?? 'online',
        cameraSettings: {
            cameraName: placeholderName,
            pictureQuality: existing?.cameraSettings?.pictureQuality ?? '1080p',
            admin: {
                fps: admin?.fps ?? 15,
                bitRate: admin?.bitRate ?? 768,
                firmwareVersion: admin?.firmwareVersion,
            },
        },
        supportedFeatures: existing?.supportedFeatures ?? {},
    };
}

// Known SimpliSafe doorbell model numbers (case-insensitive exact match).
// SS002 = Video Doorbell Pro; more may be added as the product line grows.
const SIMPLISAFE_DOORBELL_MODELS = new Set(['ss002']);

function isDoorbellCamera(details: SimplisafeCameraDetails): boolean {
    const model = (details.model ?? '').toLowerCase().trim();
    const name = (details.name ?? '').toLowerCase();
    return SIMPLISAFE_DOORBELL_MODELS.has(model) || model.includes('doorbell') || name.includes('doorbell');
}

class SimplisafeAuthManager extends EventEmitter {
    accessToken?: string;
    refreshToken?: string;
    tokenType = 'Bearer';
    expiry = 0;
    private readonly storage: Storage;
    private readonly log: Console;
    private debug: boolean;
    private codeVerifier: string;
    private readonly codeChallenge: string;

    constructor(storage: Storage, log: Console, debug: boolean) {
        super();
        this.storage = storage;
        this.log = log;
        this.debug = debug;

        this.accessToken = storage.getItem('accessToken') || undefined;
        this.refreshToken = storage.getItem('refreshToken') || undefined;
        this.tokenType = storage.getItem('tokenType') || 'Bearer';
        const storedExpiry = storage.getItem('expiry');
        if (storedExpiry) {
            this.expiry = parseInt(storedExpiry, 10);
        }

        const storedVerifier = storage.getItem('codeVerifier');
        this.codeVerifier = storedVerifier || this.base64URLEncode(crypto.randomBytes(32));
        storage.setItem('codeVerifier', this.codeVerifier);
        this.codeChallenge = this.base64URLEncode(this.sha256(Buffer.from(this.codeVerifier)));
    }

    setDebug(debug: boolean): void {
        this.debug = debug;
    }

    hasRefreshToken(): boolean {
        return !!this.refreshToken;
    }

    isAuthenticated(): boolean {
        return !!this.accessToken && Date.now() < this.expiry;
    }

    getSSAuthURL(): string {
        const loginURL = new URL(SS_OAUTH_AUTH_URL);
        loginURL.searchParams.append('client_id', SS_OAUTH_CLIENT_ID);
        loginURL.searchParams.append('scope', 'SCOPE');
        loginURL.searchParams.append('response_type', 'code');
        loginURL.searchParams.append('redirect_uri', SS_OAUTH_REDIRECT_URI);
        loginURL.searchParams.append('code_challenge_method', 'S256');
        loginURL.searchParams.append('code_challenge', this.codeChallenge);
        loginURL.searchParams.append('audience', 'AUDIENCE');
        loginURL.searchParams.append('auth0Client', SS_OAUTH_AUTH0_CLIENT);
        loginURL.searchParams.append('device', SS_OAUTH_DEVICE);
        loginURL.searchParams.append('device_id', SS_OAUTH_DEVICE_UUID);
        return loginURL.toString().replace('SCOPE', SS_OAUTH_SCOPE).replace('AUDIENCE', SS_OAUTH_AUDIENCE);
    }

    parseCodeFromURL(redirectURLStr: string): string {
        let code: string | null = null;
        try {
            const redirectURL = new URL(redirectURLStr);
            code = redirectURL.searchParams.get('code');
        } catch (error) {
            throw new Error('Invalid redirect URL');
        }

        if (!code) {
            throw new Error('Authorization code was not present in redirect URL');
        }

        return code;
    }

    async getToken(authorization: string): Promise<string> {
        const code = authorization.includes('://') ? this.parseCodeFromURL(authorization) : authorization;
        try {
            const tokenResponse = await ssOAuth.post('/token', {
                grant_type: 'authorization_code',
                client_id: SS_OAUTH_CLIENT_ID,
                code_verifier: this.codeVerifier,
                code,
                redirect_uri: SS_OAUTH_REDIRECT_URI,
            });

            await this.storeToken(tokenResponse.data);
            if (this.debug) this.log.log('Retrieved SimpliSafe access token.');
            return this.accessToken!;
        } catch (err: any) {
            throw new Error(`Error getting token: ${err?.message ?? err}`);
        }
    }

    async refreshCredentials(): Promise<void> {
        if (!this.refreshToken) {
            throw new Error('No refresh token configured. Complete authentication in the plugin settings.');
        }

        try {
            const refreshTokenResponse = await ssOAuth.post('/token', {
                grant_type: 'refresh_token',
                client_id: SS_OAUTH_CLIENT_ID,
                refresh_token: this.refreshToken,
            }, {
                headers: {
                    Host: 'auth.simplisafe.com',
                    'Content-Type': 'application/json',
                    'Auth0-Client': SS_OAUTH_AUTH0_CLIENT,
                },
            });
            await this.storeToken(refreshTokenResponse.data);
            this.emit(AUTH_EVENTS.REFRESH_CREDENTIALS_SUCCESS);
            if (this.debug) this.log.log('SimpliSafe credentials refreshed successfully.');
        } catch (err: any) {
            if (this.debug) this.log.error('SimpliSafe credentials refresh failed.', err?.message ?? err);
            this.emit(AUTH_EVENTS.REFRESH_CREDENTIALS_FAILURE);
            throw err;
        }
    }

    setRefreshToken(token?: string): void {
        this.refreshToken = token || undefined;
        if (this.refreshToken) {
            this.storage.setItem('refreshToken', this.refreshToken);
        } else {
            this.storage.removeItem('refreshToken');
        }
        this.expiry = 0;
    }

    clearTokens(): void {
        this.accessToken = undefined;
        this.refreshToken = undefined;
        this.expiry = 0;
        this.storage.removeItem('accessToken');
        this.storage.removeItem('refreshToken');
        this.storage.removeItem('expiry');
    }

    private base64URLEncode(buffer: Buffer): string {
        return buffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    private sha256(buffer: Buffer): Buffer {
        return crypto.createHash('sha256').update(buffer).digest();
    }

    private async storeToken(token: any): Promise<void> {
        this.accessToken = token.access_token;
        this.refreshToken = token.refresh_token ?? this.refreshToken;
        const expiresIn = parseInt(token.expires_in ?? '0', 10);
        const safetyWindow = 60 * 1000;
        this.expiry = Date.now() + Math.max(0, expiresIn * 1000 - safetyWindow);
        this.tokenType = token.token_type ?? 'Bearer';

        if (this.accessToken) {
            this.storage.setItem('accessToken', this.accessToken);
        } else {
            this.storage.removeItem('accessToken');
        }

        if (this.refreshToken) {
            this.storage.setItem('refreshToken', this.refreshToken);
        } else {
            this.storage.removeItem('refreshToken');
        }

        this.storage.setItem('tokenType', this.tokenType);
        this.storage.setItem('expiry', this.expiry.toString());
    }
}

class SimplisafeApi extends EventEmitter {
    private readonly authManager: SimplisafeAuthManager;
    private readonly log: Console;
    private readonly axios: AxiosInstance;
    private debug: boolean;
    private accountNumber?: string;
    private userId?: string;
    private subId?: string;
    private lastSubscription?: { id: string; data: any; timestamp: number };
    private cameraCache?: { data: SimplisafeCameraDetails[]; timestamp: number };
    // Backoff is tracked per host. api.simplisafe.com and app-hub.prd.aser.simplisafe.com are
    // separate services; letting a failure on one suppress requests to the other is what turned a
    // single refused endpoint into an outage of the whole integration.
    private backoff = new Map<string, { nextAttempt: number; interval: number }>();
    private liveViewRequests = new Map<string, Promise<LiveViewResponse>>();
    private socket?: WebSocket;
    private socketHeartbeat?: NodeJS.Timeout;
    private socketReconnect?: NodeJS.Timeout;
    private socketAlive = false;
    private isAwaitingSocketReconnect = false;
    private socketAttempts = 0;
    private socketJoinTarget?: string;

    constructor(authManager: SimplisafeAuthManager, log: Console, debug: boolean) {
        super();
        this.authManager = authManager;
        this.log = log;
        this.debug = debug;
        this.axios = axios.create({
            baseURL: 'https://api.simplisafe.com/v1',
            headers: { 'User-Agent': SS_USER_AGENT },
        });
        axiosRetry(this.axios, { retries: 2 });

        this.authManager.on(AUTH_EVENTS.REFRESH_CREDENTIALS_SUCCESS, () => {
            this.identifySocket();
        });
        this.authManager.on(AUTH_EVENTS.REFRESH_CREDENTIALS_FAILURE, () => {
            this.handleSocketConnectionFailure('auth');
        });
    }

    setDebug(debug: boolean): void {
        this.debug = debug;
    }

    setAccountNumber(accountNumber?: string): void {
        this.accountNumber = accountNumber || undefined;
        this.subId = undefined;
        this.clearCache();
    }

    clearCache(): void {
        this.userId = undefined;
        this.lastSubscription = undefined;
        this.cameraCache = undefined;
    }

    async startListening(): Promise<void> {
        if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
            this.identifySocket();
            return;
        }

        if (this.isAwaitingSocketReconnect) {
            return;
        }

        try {
            if (!this.authManager.isAuthenticated()) {
                await this.authManager.refreshCredentials();
            }
        } catch (err) {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime: authentication unavailable, skipping websocket connection.', err);
            }
            throw err;
        }

        try {
            const userId = await this.getUserId();
            if (!this.subId) {
                await this.getSubscription();
            }
            this.socketJoinTarget = `uid:${userId}`;
        } catch (err) {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime: unable to determine subscription details.', err);
            }
            throw err;
        }

        this.openSocket();
    }

    stopListening(): void {
        this.cleanupSocket();
        if (this.socketReconnect) {
            clearTimeout(this.socketReconnect);
            this.socketReconnect = undefined;
        }
        this.isAwaitingSocketReconnect = false;
        this.socketAttempts = 0;
    }

    private openSocket(): void {
        if (!this.authManager.accessToken) {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime: skipping websocket connection due to missing access token.');
            }
            return;
        }

        this.cleanupSocket();
        this.isAwaitingSocketReconnect = false;

        try {
            this.socket = new WebSocket('wss://socketlink.prd.aser.simplisafe.com', {
                handshakeTimeout: 5000,
            });
        } catch (err) {
            this.handleSocketConnectionFailure('construct');
            if (this.debug) {
                this.log.error('SimpliSafe realtime: failed to create websocket.', err);
            }
            return;
        }

        const socket = this.socket;
        socket.on('open', () => {
            if (this.debug) {
                this.log.log('SimpliSafe realtime socket opened.');
            }
            this.socketAttempts = 0;
            this.identifySocket();
        });
        socket.on('close', () => {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime socket closed.');
            }
            this.handleSocketConnectionFailure('close');
        });
        socket.on('error', (error: unknown) => {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime socket error.', error);
            }
            this.handleSocketConnectionFailure('error');
        });
        socket.on('unexpected-response', (error: unknown) => {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime socket unexpected response.', error);
            }
            this.handleSocketConnectionFailure('unexpected');
        });
        socket.on('pong', () => {
            this.socketAlive = true;
        });
        socket.on('message', (message: RawData) => this.handleSocketMessage(message));
    }

    private identifySocket(): void {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
            return;
        }
        const token = this.authManager.accessToken;
        if (!token) {
            return;
        }
        const join = this.socketJoinTarget ? [this.socketJoinTarget] : [];
        const payload = {
            datacontenttype: 'application/json',
            type: 'com.simplisafe.connection.identify',
            time: new Date().toISOString(),
            id: `ts:${Date.now()}`,
            specversion: '1.0',
            source: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            data: {
                auth: {
                    schema: 'bearer',
                    token,
                },
                join,
            },
        };
        try {
            this.socket.send(JSON.stringify(payload));
        } catch (err) {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime: identify send failed.', err);
            }
            this.handleSocketConnectionFailure('identify');
        }
    }

    private handleSocketMessage(raw: RawData): void {
        if (this.debug) {
            this.log.log(`SimpliSafe realtime: raw message: ${raw.toString()}`);
        }
        let message: SimplisafeRealtimeMessage;
        try {
            message = JSON.parse(raw.toString());
        } catch (err) {
            if (this.debug) {
                this.log.warn('SimpliSafe realtime: failed to parse message.', err);
            }
            return;
        }

        if (message.source === 'service') {
            switch (message.type) {
            case 'com.simplisafe.service.hello':
            case 'com.simplisafe.service.registered':
                break;
            case 'com.simplisafe.namespace.subscribed':
                this.socketAlive = true;
                this.scheduleHeartbeat();
                if (this.debug) {
                    this.log.log('SimpliSafe realtime events connected.');
                }
                break;
            default:
                if (this.debug) {
                    this.log.log('SimpliSafe realtime: unhandled service message.', message);
                }
                break;
            }
            return;
        }

        if (message.source !== 'messagequeue') {
            return;
        }

        const data = message.data;
        if (!data) {
            return;
        }

        if (data.sid && this.subId && data.sid !== this.subId) {
            if (this.debug) {
                this.log.log(`SimpliSafe realtime: dropping event for other subscription sid=${data.sid} (ours=${this.subId}).`);
            }
            return;
        }

        switch (data.eventCid) {
        case 1170:
            if (this.debug) {
                this.log.log(`SimpliSafe realtime: camera motion event payload: ${JSON.stringify(data)}`);
            }
            this.emit(EVENT_TYPES.CAMERA_MOTION, data);
            break;
        case 1458:
            if (this.debug) {
                this.log.log(`SimpliSafe realtime: doorbell event payload: ${JSON.stringify(data)}`);
            }
            this.emit(EVENT_TYPES.DOORBELL, data);
            break;
        default:
            if (this.debug) {
                this.log.log(`SimpliSafe realtime: unhandled event cid=${data.eventCid ?? 'unknown'} payload: ${JSON.stringify(data)}`);
            }
            break;
        }
    }

    private scheduleHeartbeat(): void {
        if (this.socketHeartbeat) {
            clearInterval(this.socketHeartbeat);
        }
        if (!this.socket) {
            return;
        }
        this.socketAlive = true;
        this.socketHeartbeat = setInterval(() => {
            if (!this.socket) {
                return;
            }
            if (!this.socketAlive) {
                if (this.debug) {
                    this.log.warn('SimpliSafe realtime heartbeat missed.');
                }
                this.handleSocketConnectionFailure('heartbeat');
                return;
            }
            this.socketAlive = false;
            try {
                this.socket.ping();
            } catch (err) {
                if (this.debug) {
                    this.log.warn('SimpliSafe realtime heartbeat ping failed.', err);
                }
                this.handleSocketConnectionFailure('heartbeat');
            }
        }, Math.min(socketHeartbeatInterval + 5000 * Math.random(), socketHeartbeatInterval * 2));
    }

    private cleanupSocket(): void {
        if (this.socketHeartbeat) {
            clearInterval(this.socketHeartbeat);
            this.socketHeartbeat = undefined;
        }
        if (this.socketReconnect) {
            clearTimeout(this.socketReconnect);
            this.socketReconnect = undefined;
        }
        const socket = this.socket;
        if (socket) {
            try {
                socket.removeAllListeners();
                socket.terminate();
            } catch (err) {
                if (this.debug) {
                    this.log.warn('SimpliSafe realtime: error closing socket.', err);
                }
            }
        }
        this.socket = undefined;
        this.socketAlive = false;
    }

    private handleSocketConnectionFailure(reason: string): void {
        this.cleanupSocket();
        if (this.isAwaitingSocketReconnect) {
            return;
        }
        this.isAwaitingSocketReconnect = true;
        const attempt = this.socketAttempts++;
        const delay = Math.min((2 ** attempt) * socketRetryInterval, socketRetryBackoffCap);
        this.socketReconnect = setTimeout(() => {
            this.isAwaitingSocketReconnect = false;
            void this.startListening().catch(err => {
                if (this.debug) {
                    this.log.warn(`SimpliSafe realtime: reconnect failed after ${reason}.`, err);
                }
            });
        }, delay);
    }

    async getAccessToken(): Promise<string> {
        if (!this.authManager.accessToken || !this.authManager.isAuthenticated()) {
            await this.authManager.refreshCredentials();
        }

        if (!this.authManager.accessToken) {
            throw new Error('Unable to retrieve SimpliSafe access token.');
        }

        return this.authManager.accessToken;
    }

    /**
     * Fetch the LiveKit live-view bundle for a newer SimpliSafe camera. Returns
     * { liveKitDetails: { liveKitURL, userToken }, cameraStatus }. Uses the app-hub host rather
     * than the standard api.simplisafe.com/v1 base (an absolute url overrides the axios baseURL).
     */
    async getLiveView(cameraUuid: string, force = false): Promise<LiveViewResponse> {
        // Consumers restart aggressively on failure (the rebroadcast prebuffer retries every 5s), so
        // collapse overlapping requests for the same camera into one upstream call. Mirrors the
        // viewerPromise memoization in LiveKitCameraStream.ensureViewer.
        const inflight = this.liveViewRequests.get(cameraUuid);
        if (inflight)
            return inflight;

        const request = (async () => {
            // Ensure the subscription/location id is resolved; getSubscription populates this.subId.
            await this.getSubscription();
            const locationId = this.subId;
            if (!locationId) {
                throw new Error('Unable to determine SimpliSafe location id for live view.');
            }

            const raw = await this.request<any>({
                method: 'GET',
                url: `https://app-hub.prd.aser.simplisafe.com/v2/cameras/${cameraUuid}/${locationId}/live-view`,
            }, { force });

            // Tolerate a wrapped envelope (e.g. { data: {...} }). The token is short-lived.
            const body: LiveViewResponse = raw?.liveKitDetails ? raw
                : raw?.data?.liveKitDetails ? raw.data
                : raw;

            if (this.debug) {
                this.log.log(`SS:liveView ${cameraUuid} liveKitURL=${body?.liveKitDetails?.liveKitURL} cameraStatus=${body?.cameraStatus}`);
            }

            return body;
        })();

        this.liveViewRequests.set(cameraUuid, request);
        try {
            return await request;
        }
        finally {
            this.liveViewRequests.delete(cameraUuid);
        }
    }

    async getCameras(forceRefresh = false): Promise<SimplisafeCameraDetails[]> {
        if (!forceRefresh && this.cameraCache && Date.now() - this.cameraCache.timestamp < cameraCacheTime) {
            if (this.debug) {
                this.log.log('SimpliSafe camera cache hit.');
            }
            return this.cameraCache.data;
        }

        try {
            if (this.debug) {
                this.log.log(`Fetching SimpliSafe cameras. forceRefresh=${forceRefresh}`);
            }

            const system = await this.getAlarmSystem(forceRefresh);
            const cameras: SimplisafeCameraDetails[] = system?.cameras ?? [];
            if (this.debug) {
                this.log.log(`Received ${cameras.length} cameras from SimpliSafe.`);
            }

            this.cameraCache = {
                data: cameras,
                timestamp: Date.now(),
            };
            return cameras;
        } catch (err) {
            if (this.cameraCache) {
                this.log.warn('SimpliSafe camera refresh failed, using cached data.', err);
                return this.cameraCache.data;
            }

            if (!forceRefresh) {
                this.log.warn('SimpliSafe camera refresh failed, retrying with force refresh.', err);
                return this.getCameras(true);
            }

            throw err;
        }
    }

    /**
     * Host the backoff for this request is keyed on. A relative url resolves against the axios
     * baseURL; getLiveView passes an absolute app-hub url.
     */
    private backoffKey(config: AxiosRequestConfig): string {
        const url = config.url ?? '';
        if (!/^https?:\/\//i.test(url))
            return 'api.simplisafe.com';
        try {
            return new URL(url).host;
        }
        catch {
            return 'api.simplisafe.com';
        }
    }

    /**
     * Log why a request failed. The response body carries the actual reason (and Kong's request_id,
     * which SimpliSafe support can correlate); discarding it is what made a hard 403 look like rate
     * limiting for weeks. Logged at warn/error so it is visible without the debug setting.
     */
    private logRequestFailure(config: AxiosRequestConfig, axiosError: AxiosError): void {
        const method = (config.method ?? 'GET').toUpperCase();
        const url = config.url ?? '';
        const response = axiosError.response;
        if (!response) {
            this.log.warn(`SimpliSafe ${method} ${url} failed with no response.`, axiosError.message);
            return;
        }

        const requestId = (response.data as any)?.request_id
            ?? (response.headers as any)?.['x-kong-request-id'];
        let body: string;
        try {
            body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        }
        catch {
            body = '<unserializable>';
        }
        this.log.error(`SimpliSafe ${method} ${url} -> ${response.status} ${response.statusText}.`
            + (requestId ? ` request_id=${requestId}.` : '')
            + ` body=${(body ?? '').slice(0, 300)}`);
    }

    /**
     * @param options.force ignore an active backoff window for one attempt. Used by user-initiated
     * actions so pressing play retries immediately instead of failing until a timer happens to expire.
     */
    private async request<T>(config: AxiosRequestConfig, options?: { force?: boolean }): Promise<T> {
        const key = this.backoffKey(config);
        const backoff = this.backoff.get(key);
        if (!options?.force && backoff && Date.now() < backoff.nextAttempt) {
            const seconds = Math.ceil((backoff.nextAttempt - Date.now()) / 1000);
            throw new RateLimitError(`Blocking request to ${key}: backing off for another ${seconds}s after a recent failure.`);
        }

        const send = async () => {
            const accessToken = await this.getAccessToken();
            return this.axios.request<T>({
                ...config,
                headers: {
                    ...config.headers,
                    Authorization: `${this.authManager.tokenType} ${accessToken}`,
                },
            });
        };

        try {
            const response = await send();
            this.resetRateLimit(key);
            return response.data;
        }
        catch (error) {
            // Local failures (no access token, bad config) are not HTTP problems and must not be
            // reported as rate limiting.
            if (!axios.isAxiosError(error))
                throw error;

            const axiosError = error as AxiosError;

            // A 401 means the token went stale, not that the account is blocked. Refresh once and
            // retry before giving up; on failure fall through to the 401 branch below.
            if (axiosError.response?.status === 401) {
                try {
                    await this.authManager.refreshCredentials();
                    const response = await send();
                    this.resetRateLimit(key);
                    return response.data;
                }
                catch {
                    // fall through with the original 401
                }
            }

            this.logRequestFailure(config, axiosError);

            if (!axiosError.response) {
                this.setRateLimit(key);
                throw new RateLimitError('SimpliSafe request failed: no response received.');
            }

            const status = axiosError.response.status;

            // 429 is the only status that actually means rate limited.
            if (status === 429) {
                const retryAfter = Number((axiosError.response.headers as any)?.['retry-after']);
                this.setRateLimit(key, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : undefined);
                throw new RateLimitError(`SimpliSafe rate limited requests to ${key}.`);
            }

            if (status === 401)
                throw new Error('SimpliSafe rejected the stored credentials. Re-authenticate in the plugin settings.');

            // A 403 is a deterministic refusal, not congestion. Backing off would only delay an
            // identical failure, and suppressing the host would take unrelated features down with
            // it — see SS_USER_AGENT for the gateway filter that lands here.
            if (status === 403)
                throw new Error(`SimpliSafe refused the request to ${key} (403 Forbidden). See the logged response body for the reason.`);

            throw axiosError.response.data ?? axiosError;
        }
    }

    private resetRateLimit(key: string): void {
        this.backoff.delete(key);
    }

    private setRateLimit(key: string, retryAfterMs?: number): void {
        const previous = this.backoff.get(key)?.interval ?? 0;
        const interval = retryAfterMs
            ?? Math.min(previous ? previous * 2 : rateLimitInitialInterval, rateLimitMaxInterval);
        this.backoff.set(key, { nextAttempt: Date.now() + interval, interval });
    }

    private async getUserId(): Promise<string> {
        if (this.userId) {
            return this.userId;
        }

        const data = await this.request<{ userId: string }>({
            method: 'GET',
            url: '/api/authCheck',
        });
        this.userId = data.userId;
        return this.userId;
    }

    private async getSubscriptions(): Promise<any[]> {
        const userId = await this.getUserId();
        const data = await this.request<{ subscriptions: any[] }>({
            method: 'GET',
            url: `/users/${userId}/subscriptions?activeOnly=false`,
        });

        let subscriptions = data.subscriptions.filter(s => [7, 10, 20].includes(s.sStatus));
        if (this.accountNumber) {
            subscriptions = subscriptions.filter(s => s.location?.account === this.accountNumber);
        }

        if (subscriptions.length > 1) {
            subscriptions = subscriptions.filter(s => s.activated > 0);
        }

        if (subscriptions.length === 1) {
            this.subId = subscriptions[0].sid;
        }

        return subscriptions;
    }

    private async getSubscription(forceRefresh = false): Promise<any> {
        let subscriptionId = this.subId;

        if (!subscriptionId) {
            const subscriptions = await this.getSubscriptions();
            if (subscriptions.length === 1) {
                subscriptionId = subscriptions[0].sid;
                this.subId = subscriptionId;
            } else if (subscriptions.length === 0) {
                throw new Error('No active SimpliSafe monitoring plan found for this account.');
            } else {
                const accounts = subscriptions.map(s => s.location?.account).filter(Boolean);
                throw new Error(`Multiple SimpliSafe accounts found. Specify an account number in the plugin settings. Accounts: ${accounts.join(', ')}`);
            }
        }

        if (!subscriptionId) {
            throw new Error('Unable to determine SimpliSafe subscription identifier.');
        }

        const shouldFetch = forceRefresh
            || !this.lastSubscription
            || this.lastSubscription.id !== subscriptionId
            || Date.now() - this.lastSubscription.timestamp > subscriptionCacheTime;

        if (shouldFetch) {
            const subscription = await this.request<any>({
                method: 'GET',
                url: `/subscriptions/${subscriptionId}/`,
            });
            this.lastSubscription = {
                id: subscriptionId,
                data: subscription?.subscription ?? subscription,
                timestamp: Date.now(),
            };
        }

        return this.lastSubscription!.data;
    }

    private async getAlarmSystem(forceRefresh = false): Promise<any> {
        const subscription = await this.getSubscription(forceRefresh);
        const system = subscription?.location?.system;
        if (!system) {
            throw new Error('SimpliSafe subscription data did not include system details.');
        }
        return system;
    }
}

class SimplisafeCamera extends ScryptedDeviceBase implements Camera, VideoCamera, Settings, MotionSensor, BinarySensor, RTCSignalingChannel, Intercom {
    private static instanceRegistry = new Map<string, string>();
    private readonly nativeCameraId: string;
    private readonly api: SimplisafeApi;
    private readonly authManager: SimplisafeAuthManager;
    private readonly getDebug: DebugProvider;
    private readonly detailsCallback: (details: SimplisafeCameraDetails) => void;
    private readonly statusCallback: (ready: boolean, desiredOnline: boolean) => void;
    private readonly instanceId: string;
    private details?: SimplisafeCameraDetails;
    private liveKitStream?: LiveKitCameraStream;
    private streamOptions?: ResponseMediaStreamOptions[];
    private pictureOptions?: ResponsePictureOptions[];
    private simplisafeUuid?: string;
    private ready = false;
    private desiredOnline = true;
    private motionResetTimer?: NodeJS.Timeout;
    private readonly motionHoldDurationMs = 5_000;
    // NOTE: motionDetected must NOT be re-declared as a class field here. Under
    // useDefineForClassFields (target ESNext) a field declaration installs an own
    // property that shadows ScryptedDeviceBase's prototype accessor, so assignments
    // would never reach Scrypted device state (or HomeKit).
    motionDetectedTimestamp?: number;
    private doorbellResetTimer?: NodeJS.Timeout;
    private readonly doorbellHoldDurationMs = 5_000;
    private intercomProcess?: ChildProcess;
    private intercomSocket?: dgram.Socket;
    private intercomCleanup?: () => void;
    private snapshotCache?: Buffer;
    private snapshotCacheTime = 0;
    private snapshotRefresh?: Promise<Buffer | undefined>;
    private disposed = false;
    private snapshotTimer?: NodeJS.Timeout;
    private intercomGeneration = 0;

    constructor(
        nativeId: string,
        simplisafeUuid: string | undefined,
        api: SimplisafeApi,
        authManager: SimplisafeAuthManager,
        getDebug: DebugProvider,
        detailsCallback: (details: SimplisafeCameraDetails) => void,
        statusCallback: (ready: boolean, desiredOnline: boolean) => void,
    ) {
        super(nativeId);
        this.nativeCameraId = nativeId;
        this.api = api;
        this.authManager = authManager;
        this.getDebug = getDebug;
        this.simplisafeUuid = simplisafeUuid;
        this.detailsCallback = detailsCallback;
        this.statusCallback = statusCallback;
        this.instanceId = Math.random().toString(36).slice(2);
        this.motionDetected = false;

        const existing = SimplisafeCamera.instanceRegistry.get(nativeId);
        if (existing && existing !== this.instanceId) {
            throw new Error(`Duplicate SimplisafeCamera instance for ${nativeId}. existing=${existing} new=${this.instanceId}`);
        }
        SimplisafeCamera.instanceRegistry.set(nativeId, this.instanceId);
        this.console.log('Camera instance created', this.nativeCameraId, this.instanceId);
    }

    private notifyStatus(): void {
        this.statusCallback(this.ready, this.desiredOnline);
    }

    private logInstanceUsage(context: string): void {
        this.console.log('Camera instance used', this.nativeCameraId, this.instanceId, context);
    }

    dispose(): void {
        if (this.disposed)
            return;
        this.disposed = true;
        void this.stopIntercom();
        this.liveKitStream?.close();
        this.liveKitStream = undefined;
        if (this.snapshotTimer)
            clearTimeout(this.snapshotTimer);
        const current = SimplisafeCamera.instanceRegistry.get(this.nativeCameraId);
        if (current === this.instanceId) {
            SimplisafeCamera.instanceRegistry.delete(this.nativeCameraId);
        }
        if (this.motionResetTimer) {
            clearTimeout(this.motionResetTimer);
            this.motionResetTimer = undefined;
        }
        if (this.doorbellResetTimer) {
            clearTimeout(this.doorbellResetTimer);
            this.doorbellResetTimer = undefined;
        }
    }
    updateDetails(details: SimplisafeCameraDetails): void {
        this.logInstanceUsage('updateDetails');
        this.details = details;
        this.streamOptions = undefined;
        this.pictureOptions = undefined;
        if (this.getDebug()) {
            this.console.log(`Updated details for ${this.nativeCameraId}. Name=${details.name ?? details.cameraSettings?.cameraName ?? this.nativeCameraId}, Status=${details.status}, PictureQuality=${details.cameraSettings?.pictureQuality}`);
        }
        if (details.uuid) {
            this.simplisafeUuid = details.uuid;
        }
        this.desiredOnline = details.status ? details.status === 'online' : true;
        this.detailsCallback(details);
        this.notifyStatus();
    }

    private async ensureDetails(forceRefresh = false): Promise<SimplisafeCameraDetails> {
        if (!forceRefresh && this.details) {
            return this.details;
        }

        try {
            const cameras = await this.api.getCameras(forceRefresh);
            const details = cameras.find(camera => this.matchesCamera(camera));
            if (details) {
                if (this.getDebug()) {
                    this.console.log(`SS:rawCameraDetails ${this.nativeCameraId} ${JSON.stringify(details)}`);
                }
                this.updateDetails(details);
                return details;
            }
        } catch (err) {
            if (this.getDebug()) {
                this.console.warn(`Failed to refresh SimpliSafe camera ${this.getDisplayName()}.`, err);
            }

            if (!this.details) {
                this.updateDetails(this.createPlaceholderDetails());
            }

            return this.details!;
        }

        if (!forceRefresh) {
            return this.ensureDetails(true);
        }

        if (this.details) {
            return this.details;
        }

        this.updateDetails(this.createPlaceholderDetails());
        this.console.warn(`SimpliSafe camera ${this.nativeCameraId} is using placeholder configuration due to missing device metadata.`);
        return this.details!;
    }

    markReady(): void {
        this.logInstanceUsage('markReady');
        if (!this.ready) {
            this.ready = true;
            if (this.getDebug()) {
                this.console.log(`SimpliSafe camera ${this.nativeCameraId} marked ready for streaming.`);
            }
            this.notifyStatus();
        }
    }

    isStreamingReady(): boolean {
        return this.ready;
    }

    handleMotionEvent(event: SimplisafeRealtimeEvent): void {
        this.logInstanceUsage('motionEvent');
        const timestampCandidates: (number | undefined)[] = [];
        if (typeof event?.timestamp === 'number') {
            timestampCandidates.push(event.timestamp);
        }
        if (typeof event?.detectedAt === 'number') {
            timestampCandidates.push(event.detectedAt);
        } else if (typeof event?.detectedAt === 'string') {
            const parsed = Date.parse(event.detectedAt);
            if (!Number.isNaN(parsed)) {
                timestampCandidates.push(parsed);
            }
        }
        const now = Date.now();
        const chosenTimestamp = timestampCandidates.find(value => typeof value === 'number' && Number.isFinite(value)) ?? now;
        this.motionDetectedTimestamp = chosenTimestamp;
        if (this.getDebug()) {
            this.console.log(`SimpliSafe motion detected for ${this.nativeCameraId} at ${new Date(chosenTimestamp).toISOString()}.`);
        }

        this.motionDetected = true;
        if (this.motionResetTimer) {
            clearTimeout(this.motionResetTimer);
        }
        this.motionResetTimer = setTimeout(() => {
            this.motionResetTimer = undefined;
            this.motionDetected = false;
        }, this.motionHoldDurationMs);
    }

    handleDoorbellEvent(event: SimplisafeRealtimeEvent): void {
        this.logInstanceUsage('doorbellEvent');
        if (this.getDebug()) {
            this.console.log(`SimpliSafe doorbell press detected for ${this.nativeCameraId}.`);
        }
        this.binaryState = true;
        if (this.doorbellResetTimer) {
            clearTimeout(this.doorbellResetTimer);
        }
        this.doorbellResetTimer = setTimeout(() => {
            this.doorbellResetTimer = undefined;
            this.binaryState = false;
        }, this.doorbellHoldDurationMs);
    }

    async prepareForStreaming(): Promise<boolean> {
        this.logInstanceUsage('prepareForStreaming');
        try {
            await this.api.getAccessToken();
            await this.getVideoStreamOptions();
            this.markReady();
            return true;
        } catch (err) {
            if (this.getDebug()) {
                this.console.warn(`SimpliSafe camera ${this.nativeCameraId} failed readiness probe.`, err);
            }
            return false;
        }
    }

    private matchesCamera(candidate: SimplisafeCameraDetails): boolean {
        if (candidate.uuid && this.simplisafeUuid && candidate.uuid === this.simplisafeUuid) {
            return true;
        }

        if (candidate.uuid && candidate.uuid === this.nativeCameraId) {
            return true;
        }

        const derivedId = deriveCameraNativeId(candidate);
        return derivedId === this.nativeCameraId;
    }

    private createPlaceholderDetails(): SimplisafeCameraDetails {
        return buildPlaceholderCameraDetails(this.nativeCameraId, this.details, this.getDisplayName(), this.simplisafeUuid);
    }

    async getVideoStreamOptions(): Promise<ResponseMediaStreamOptions[]> {
        this.logInstanceUsage('getVideoStreamOptions');
        if (this.getDebug())
            this.console.log('SS:getVideoStreamOptions', this.nativeCameraId);
        try {
            const details = await this.ensureDetails();

            if (!this.streamOptions) {
                this.streamOptions = this.buildStreamOptions(details);
            }

            return this.streamOptions;
        } catch (err) {
            this.console.error(`Failed to retrieve SimpliSafe stream options for ${this.nativeCameraId}.`, err);
            throw err;
        }
    }

    async getVideoStream(options?: RequestMediaStreamOptions): Promise<MediaObject> {
        this.logInstanceUsage('getVideoStream');
        if (this.getDebug())
            this.console.log('SS:getVideoStream', this.nativeCameraId, options);
        try {
            const details = await this.ensureDetails();

            if (this.isLiveKitCamera(details)) {
                throw new Error(`${this.getDisplayName()} streams over WebRTC; use the RTCSignalingChannel path, not getVideoStream.`);
            }

            if (this.isUnsupported(details)) {
                throw new Error(`${this.getDisplayName()} does not support SimpliSafe cloud streaming.`);
            }

            const streamOptions = await this.getVideoStreamOptions();
            let selected: ResponseMediaStreamOptions | undefined;
            if (options?.id) {
                selected = streamOptions.find(o => o.id === options.id);
            }
            selected = selected ?? streamOptions[streamOptions.length - 1];

            const width = selected.video?.width ?? 1920;
            const accessToken = await this.api.getAccessToken();
            const url = `https://${SS_MEDIA_HOST}/v1/${details.uuid}/flv?x=${width}&audioEncoding=AAC`;
            const inputArguments = [
                '-re',
                // ffmpeg skips TLS certificate verification by default; the Authorization header
                // below must not be exposed to a MITM.
                '-tls_verify', '1',
                '-headers',
                `Authorization: Bearer ${accessToken}`,
                '-i',
                url,
            ];

            const ffmpegInput: FFmpegInput = {
                inputArguments,
                mediaStreamOptions: selected,
                container: 'flv',
            };

            this.console.log(`${this.getDisplayName()} streaming via ${url}`);

            return mediaManager.createFFmpegMediaObject(ffmpegInput);
        } catch (err) {
            this.console.error(`Failed to start SimpliSafe stream for ${this.nativeCameraId}.`, err);
            throw err;
        }
    }

    async takePicture(options?: RequestPictureOptions): Promise<MediaObject> {
        this.logInstanceUsage('takePicture');
        const details = await this.ensureDetails();

        // LiveKit cameras have no snapshot endpoint. Instead of cold-starting the WebRTC->RTSP path
        // on every request (slow, and prone to timing out as "Snapshot Failed" in HomeKit), serve a
        // JPEG decoded from the live stream's latest keyframe, cached so idle cameras answer instantly.
        if (this.isLiveKitCamera(details)) {
            const jpeg = await this.getLiveKitSnapshot();
            if (jpeg?.length) {
                return this.createMediaObject(jpeg, 'image/jpeg');
            }
            // Nothing streamed yet and nothing cached: fall back to Scrypted's Snapshot plugin, which
            // derives (and caches) a still from the rebroadcast prebuffer.
            throw new Error(`${this.getDisplayName()} does not support direct snapshot capture; derived from the WebRTC stream.`);
        }

        try {
            if (this.isUnsupported(details)) {
                throw new Error(`${this.getDisplayName()} does not support snapshots.`);
            }

            const streamOptions = await this.getVideoStreamOptions();
            const preferred = streamOptions[streamOptions.length - 1];
            const width = options?.picture?.width
                ?? preferred.video?.width
                ?? 1920;

            const accessToken = await this.api.getAccessToken();
            const snapshotUrl = `https://${SS_MEDIA_HOST}/v1/${details.uuid}/mjpg?x=${width}&fr=1`;

            const image = await jpegExtract({
                url: snapshotUrl,
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            });

            return this.createMediaObject(image, 'image/jpeg');
        } catch (err) {
            this.console.error(`Failed to capture SimpliSafe snapshot for ${this.nativeCameraId}.`, err);
            throw err;
        }
    }

    /**
     * Produce a still for a LiveKit (WebRTC) camera. When a stream is active we decode its latest
     * H264 keyframe to JPEG and cache it; when idle we serve that cached JPEG immediately. This keeps
     * HomeKit snapshots instant instead of cold-starting the WebRTC->RTSP path, which is slow and
     * frequently times out as "Snapshot Failed" once the camera has gone idle for a while.
     */
    private async getLiveKitSnapshot(): Promise<Buffer | undefined> {
        const keyframe = this.liveKitStream?.getKeyframe();
        // Refresh from a live keyframe at most every few seconds; otherwise reuse the cached JPEG.
        if (keyframe && Date.now() - this.snapshotCacheTime > 3_000) {
            if (!this.snapshotRefresh) {
                this.snapshotRefresh = this.decodeKeyframeToJpeg(keyframe)
                    .then(jpeg => {
                        if (jpeg?.length) {
                            this.snapshotCache = jpeg;
                            this.snapshotCacheTime = Date.now();
                        }
                        return jpeg;
                    })
                    .catch(err => {
                        this.console.warn(`Failed to decode SimpliSafe keyframe snapshot for ${this.nativeCameraId}.`, err);
                        return undefined;
                    })
                    .finally(() => { this.snapshotRefresh = undefined; });
            }
            // With no cached image yet, wait for the decode; otherwise serve the stale cache now and
            // let the refresh finish in the background so this request stays fast.
            if (!this.snapshotCache) {
                await this.snapshotRefresh;
            }
        }
        return this.snapshotCache;
    }

    /** Decode a single Annex-B H264 keyframe to a JPEG using ffmpeg. */
    private async decodeKeyframeToJpeg(keyframe: Buffer): Promise<Buffer | undefined> {
        const ffmpegPath = await mediaManager.getFFmpegPath();
        return await new Promise<Buffer | undefined>((resolve, reject) => {
            const args = [
                '-hide_banner', '-loglevel', 'error',
                '-f', 'h264',
                '-i', 'pipe:0',
                '-frames:v', '1',
                '-f', 'mjpeg',
                'pipe:1',
            ];
            const cp = spawn(ffmpegPath, args);
            const out: Buffer[] = [];
            const err: Buffer[] = [];
            const timer = setTimeout(() => {
                try { cp.kill('SIGKILL'); } catch { /* ignore */ }
                reject(new Error('SimpliSafe snapshot decode timed out.'));
            }, 5_000);
            cp.stdout.on('data', d => out.push(d));
            cp.stderr.on('data', d => err.push(d));
            cp.on('error', e => { clearTimeout(timer); reject(e); });
            cp.on('close', code => {
                clearTimeout(timer);
                const jpeg = Buffer.concat(out);
                if (jpeg.length)
                    resolve(jpeg);
                else
                    reject(new Error(`ffmpeg snapshot decode failed (code ${code}): ${Buffer.concat(err).toString().trim()}`));
            });
            cp.stdin.on('error', () => { /* ignore EPIPE if ffmpeg exits before we finish writing */ });
            cp.stdin.write(keyframe);
            cp.stdin.end();
        });
    }

    async getPictureOptions(): Promise<ResponsePictureOptions[]> {
        this.logInstanceUsage('getPictureOptions');
        await this.ensureDetails();

        if (!this.pictureOptions) {
            const streamOptions = await this.getVideoStreamOptions();
            const preferred = streamOptions[streamOptions.length - 1];
            this.pictureOptions = [
                {
                    id: 'default',
                    name: 'Snapshot',
                    picture: preferred.video ? {
                        width: preferred.video.width,
                        height: preferred.video.height,
                    } : undefined,
                    canResize: true,
                },
            ];
        }

        return this.pictureOptions;
    }

    private buildStreamOptions(details: SimplisafeCameraDetails): ResponseMediaStreamOptions[] {
        const resolutions: [number, number, number?][] = [
            [320, 180],
            [320, 240],
            [480, 270],
            [480, 360],
            [640, 360],
            [640, 480],
            [1280, 720],
            [1920, 1080],
        ];

        const admin = details.cameraSettings?.admin;
        const fps = admin?.fps ?? 15;
        const maxHeight = this.getMaxSupportedHeight(details);

        const filtered = resolutions.filter(([, height]) => height <= maxHeight);
        return filtered.map(([width, height]) => ({
            id: `${width}x${height}`,
            name: `${width}x${height}`,
            container: 'flv',
            tool: 'ffmpeg',
            source: 'local',
            video: {
                codec: 'h264',
                width,
                height,
                fps,
                bitrate: admin?.bitRate ? admin.bitRate * 1000 : undefined,
            },
            audio: {
                codec: 'aac',
                sampleRate: 16000,
            },
        }));
    }

    private getMaxSupportedHeight(details: SimplisafeCameraDetails): number {
        const quality = details.cameraSettings?.pictureQuality;
        if (!quality) {
            return 1080;
        }

        const match = quality.match(/(\d+)/);
        if (!match) {
            return 1080;
        }

        const height = parseInt(match[1], 10);
        if (!Number.isFinite(height)) {
            return 1080;
        }

        return height;
    }

    private getCameraName(details: SimplisafeCameraDetails): string {
        return details.cameraSettings?.cameraName || details.name || `Camera ${details.uuid}`;
    }

    private getDisplayName(): string {
        if (this.details) {
            return this.getCameraName(this.details);
        }
        return `Camera ${this.nativeCameraId}`;
    }

    /**
     * Newer SimpliSafe cameras stream over LiveKit (WebRTC), reported as providers.webrtc === 'kvs'
     * (and typically live === 'none'), instead of the legacy FLV endpoint.
     */
    isLiveKitCamera(details: SimplisafeCameraDetails): boolean {
        return isLiveKitCameraDetails(details);
    }

    private isUnsupported(details: SimplisafeCameraDetails): boolean {
        // LiveKit cameras are supported via the WebRTC/RTCSignalingChannel path, not FLV.
        if (this.isLiveKitCamera(details)) {
            return false;
        }
        const provider = details.supportedFeatures?.providers?.recording;
        const unsupported = provider !== undefined && !SUPPORTED_RECORDING_PROVIDERS.has(provider);
        if (unsupported && this.getDebug()) {
            this.console.log(
                `SS:isUnsupported ${this.getDisplayName()} recordingProvider=${JSON.stringify(provider)} ` +
                `supportedFeatures=${JSON.stringify(details.supportedFeatures)}`);
        }
        return unsupported;
    }

    async startRTCSignalingSession(session: RTCSignalingSession): Promise<RTCSessionControl | undefined> {
        this.logInstanceUsage('startRTCSignalingSession');
        const details = await this.ensureDetails();
        if (!this.isLiveKitCamera(details)) {
            throw new Error(`${this.getDisplayName()} does not support WebRTC streaming.`);
        }

        try {
            const control = await this.getLiveKitStream(details.uuid).startSession(session);
            // Seed/refresh the snapshot cache from the now-warm stream so the HomeKit thumbnail is
            // fresh and later idle snapshots answer instantly instead of cold-starting (and timing
            // out). The stream sends a keyframe on connect; give it a moment to arrive.
            if (this.snapshotTimer)
                clearTimeout(this.snapshotTimer);
            this.snapshotTimer = setTimeout(() => { this.getLiveKitSnapshot().catch(() => { /* ignore */ }); }, 3_000);
            return control;
        } catch (err) {
            this.console.error(`Failed to start SimpliSafe WebRTC stream for ${this.nativeCameraId}.`, err);
            throw err;
        }
    }

    /** One shared LiveKit connection per camera, fanned out to all Scrypted consumers. */
    private getLiveKitStream(cameraUuid: string): LiveKitCameraStream {
        if (this.disposed)
            throw new Error('SimpliSafe camera disposed.');
        if (!this.liveKitStream) {
            this.liveKitStream = new LiveKitCameraStream(async (force?: boolean) => {
                const liveView = await this.api.getLiveView(cameraUuid, force);
                const liveKit = liveView.liveKitDetails;
                if (!liveKit?.liveKitURL || !liveKit?.userToken) {
                    throw new Error(`${this.getDisplayName()} live-view response did not include LiveKit details.`);
                }
                if (this.getDebug()) {
                    this.console.log(`SS:liveView ${this.nativeCameraId} liveKitURL=${liveKit.liveKitURL} cameraStatus=${liveView.cameraStatus}`);
                }
                return liveKit;
            }, this.console, this.getDebug);
        }
        return this.liveKitStream;
    }

    /**
     * Two-way audio (talk-back). Scrypted/HomeKit hands us the return audio as an FFmpegInput; we
     * transcode it to Opus RTP, feed it to a werift track, and publish that track upstream to
     * LiveKit over the shared participant connection.
     */
    async startIntercom(media: MediaObject): Promise<void> {
        this.logInstanceUsage('startIntercom');
        const details = await this.ensureDetails();
        if (!this.isLiveKitCamera(details)) {
            throw new Error(`${this.getDisplayName()} does not support two-way audio.`);
        }

        // Tear down any prior intercom session before starting a new one.
        const stopped = this.stopIntercom();
        const generation = this.intercomGeneration;
        await stopped;
        const assertCurrent = () => {
            if (this.disposed || generation !== this.intercomGeneration)
                throw new Error('SimpliSafe intercom start cancelled.');
        };

        const ffmpegInput = await mediaManager.convertMediaObjectToJSON<FFmpegInput>(media, ScryptedMimeTypes.FFmpegInput);
        const ffmpegPath = await mediaManager.getFFmpegPath();

        try {
            assertCurrent();
            // Acquire the shared LiveKit talk-back sink (published once, reused across sessions).
            const sink = await this.getLiveKitStream(details.uuid).acquireMicSink();
            if (this.disposed || generation !== this.intercomGeneration) {
                sink.release();
                throw new Error('SimpliSafe intercom start cancelled.');
            }
            this.intercomCleanup = sink.release;

            // Bind a UDP socket so we can tell ffmpeg which port to emit Opus RTP to.
            const socket = dgram.createSocket('udp4');
            this.intercomSocket = socket;
            // An unhandled dgram 'error' would surface as an uncaughtException and kill the plugin.
            socket.on('error', err => this.console.error('SimpliSafe intercom socket error.', err));
            const port = await new Promise<number>((resolve, reject) => {
                socket.once('error', reject);
                socket.bind(0, '127.0.0.1', () => resolve(socket.address().port));
            });
            assertCurrent();

            socket.on('message', buf => {
                try {
                    // Resolve the track per packet: after a forced mid-talk session rollover the
                    // shared mic lives on the replacement viewer, not the one at acquire time.
                    const track = sink.getTrack();
                    if (!track)
                        return;
                    const pkt = RtpPacket.deSerialize(buf);
                    pkt.header.payloadType = track.codec?.payloadType ?? 111;
                    track.writeRtp(pkt);
                }
                catch {
                    /* ignore malformed packet */
                }
            });

            const args = [
                ...ffmpegInput.inputArguments!,
                '-vn',
                '-acodec', 'libopus',
                '-ac', '2',
                '-ar', '48000',
                '-application', 'lowdelay',
                '-f', 'rtp',
                '-payload_type', '111',
                `rtp://127.0.0.1:${port}`,
            ];
            if (this.getDebug())
                this.console.log('SS:startIntercom ffmpeg', ffmpegPath, args.join(' '));

            const cp = spawn(ffmpegPath, args, {
                env: ffmpegInput.env ? { ...process.env, ...ffmpegInput.env } : process.env,
            });
            this.intercomProcess = cp;
            const stopCurrent = () => {
                if (this.intercomProcess === cp)
                    this.stopIntercom().catch(() => { /* ignore */ });
            };
            cp.on('error', err => {
                this.console.error('SimpliSafe intercom ffmpeg error.', err);
                stopCurrent();
            });
            cp.stderr?.on('data', data => {
                if (this.getDebug())
                    this.console.log('SS:intercom ffmpeg', data.toString());
            });
            cp.on('exit', stopCurrent);
        }
        catch (err) {
            this.console.error(`Failed to start SimpliSafe talk-back for ${this.nativeCameraId}.`, err);
            if (generation === this.intercomGeneration)
                await this.stopIntercom();
            throw err;
        }
    }

    async stopIntercom(): Promise<void> {
        this.logInstanceUsage('stopIntercom');
        this.intercomGeneration++;
        try { this.intercomCleanup?.(); } catch { /* ignore */ }
        this.intercomCleanup = undefined;
        try { this.intercomProcess?.kill('SIGKILL'); } catch { /* ignore */ }
        this.intercomProcess = undefined;
        try { this.intercomSocket?.close(); } catch { /* ignore */ }
        this.intercomSocket = undefined;
    }

    async getSettings(): Promise<Setting[]> {
        this.logInstanceUsage('getSettings');
        return [];
    }

    async putSetting(key: string, value: SettingValue): Promise<void> {
        this.logInstanceUsage(`putSetting:${key}`);
        if (this.getDebug()) {
            this.console.log(`Ignoring setting ${key} update for SimpliSafe camera ${this.nativeCameraId}.`);
        }
    }
}

class SimplisafePlugin extends ScryptedDeviceBase implements DeviceProvider, Settings {
    private readonly devices = new Map<string, SimplisafeCamera>();
    private readonly cameraDetails = new Map<string, SimplisafeCameraDetails>();
    private readonly nativeIdToUuid = new Map<string, string>();
    private readonly uuidToNativeId = new Map<string, string>();
    private readonly identifierToNativeIds = new Map<string, Set<string>>();
    private readonly currentNativeIds = new Set<string>();
    private readonly deviceCreations = new Map<string, Promise<SimplisafeCamera>>();
    private readonly readinessTasks = new Map<string, Promise<void>>();
    private readonly upgradedNativeIds = new Set<string>();
    private readonly readinessStorageKey = 'cameraReadiness';
    private readonly cameraReady = new Map<string, boolean>();
    private readonly cameraDesiredOnline = new Map<string, boolean>();
    private readonly cameraLastOnline = new Map<string, boolean>();
    private readonly lastPublished = new Map<string, string>();
    private readonly publishTimers = new Map<string, NodeJS.Timeout>();
    private readonly cachedDescriptors = new Map<string, CachedCameraDescriptor>();
    private readonly pendingRemoval = new Map<string, number>();
    private syncing = false;
    private hasDumpedSystemState = false;
    private readonly authManager: SimplisafeAuthManager;
    private readonly api: SimplisafeApi;
    private debug: boolean;
    private accountNumber?: string;
    private initializing?: Promise<void>;
    private persistCameraDetailsTimer?: NodeJS.Timeout;
    private pendingRemovalTimer?: NodeJS.Timeout;

    constructor() {
        super();
        this.console.log('testing version 1.2');
        this.debug = this.storage.getItem('debug') === 'true';
        const storedAccount = this.storage.getItem('accountNumber');
        this.accountNumber = storedAccount || undefined;

        this.authManager = new SimplisafeAuthManager(this.storage, this.console, this.debug);
        this.api = new SimplisafeApi(this.authManager, this.console, this.debug);
        this.api.setAccountNumber(this.accountNumber);
        this.api.on(EVENT_TYPES.CAMERA_MOTION, event => this.handleCameraMotionEvent(event));
        this.api.on(EVENT_TYPES.DOORBELL, event => this.handleDoorbellPressEvent(event));

        this.loadCachedCameras();
        this.loadCameraReadiness();
        this.loadCachedDescriptors();
        this.republishCachedDescriptors().catch(err => {
            this.console.warn('Failed to republish cached SimpliSafe descriptors during startup.', err);
        });
        this.maintenanceCleanup();
        this.initializing = this.initialize();
    }

    private normalizeNativeId(id: string): string {
        return (id ?? '').trim().toLowerCase();
    }

    private associateUuidWithNativeId(uuid: string | undefined, nativeId: string): void {
        if (!uuid) {
            return;
        }
        this.uuidToNativeId.set(uuid, nativeId);
        this.uuidToNativeId.set(uuid.toLowerCase(), nativeId);
    }

    private removeUuidAssociation(uuid: string | undefined): void {
        if (!uuid) {
            return;
        }
        this.uuidToNativeId.delete(uuid);
        this.uuidToNativeId.delete(uuid.toLowerCase());
    }

    private registerCameraIdentifiers(nativeId: string, details: SimplisafeCameraDetails): void {
        const normalizedNativeId = this.normalizeNativeId(nativeId);
        this.unregisterCameraIdentifiers(normalizedNativeId);
        const identifiers: (string | undefined)[] = [
            (details as any)?.serialNumber,
            (details as any)?.serial,
            (details as any)?.deviceSerial,
            (details as any)?.macAddress,
            (details as any)?.mac,
            details.uuid,
        ];
        for (const identifier of identifiers) {
            if (typeof identifier !== 'string') {
                continue;
            }
            const trimmed = identifier.trim();
            if (!trimmed) {
                continue;
            }
            for (const key of new Set([trimmed.toLowerCase(), normalizeIdSegment(trimmed)])) {
                if (!key) {
                    continue;
                }
                let nativeIds = this.identifierToNativeIds.get(key);
                if (!nativeIds) {
                    nativeIds = new Set<string>();
                    this.identifierToNativeIds.set(key, nativeIds);
                }
                nativeIds.add(normalizedNativeId);
            }
        }
    }

    private unregisterCameraIdentifiers(nativeId: string): void {
        const normalizedNativeId = this.normalizeNativeId(nativeId);
        for (const [key, nativeIds] of this.identifierToNativeIds) {
            if (nativeIds.delete(normalizedNativeId) && nativeIds.size === 0) {
                this.identifierToNativeIds.delete(key);
            }
        }
    }

    private handleCameraMotionEvent(event: SimplisafeRealtimeEvent): void {
        const nativeIds = this.resolveNativeIdsFromEvent(event);
        if (nativeIds.length === 0) {
            const identifier = event.sensorSerial
                || event.cameraSerial
                || event.serial
                || event.deviceSerial
                || event.cameraUuid
                || event.uuid;
            this.console.warn(`SimpliSafe motion event could not be matched to a camera. identifier=${identifier ?? 'unknown'}`);
            if (this.debug) {
                this.console.warn(`Unmatched motion event payload: ${JSON.stringify(event)}`);
            }
            return;
        }

        for (const nativeId of nativeIds) {
            void this.dispatchMotionEvent(nativeId, event);
        }
    }

    private resolveNativeIdsFromEvent(event: SimplisafeRealtimeEvent): string[] {
        const candidates = new Set<string>();
        const collect = (value?: string) => {
            if (typeof value === 'string') {
                const trimmed = value.trim();
                if (trimmed) {
                    candidates.add(trimmed);
                }
            }
        };
        collect(event.sensorSerial);
        collect(event.cameraSerial);
        collect(event.serial);
        collect(event.deviceSerial);
        collect(event.cameraUuid);
        collect(event.uuid);
        if (event.internal && typeof event.internal === 'object') {
            const internal = event.internal as SimplisafeRealtimeInternalDetails;
            collect(internal.mainCamera);
        }

        const resolved = new Set<string>();
        for (const candidate of candidates) {
            // The event may carry the nativeId itself, a bare serial/uuid, or a
            // serial that only matches after full segment normalization.
            const normalized = this.normalizeNativeId(candidate);
            if (this.cameraDetails.has(normalized)) {
                resolved.add(normalized);
            }
            const prefixed = `simplisafe-camera-${normalizeIdSegment(candidate)}`;
            if (this.cameraDetails.has(prefixed)) {
                resolved.add(prefixed);
            }
            const mapped = this.uuidToNativeId.get(candidate) ?? this.uuidToNativeId.get(candidate.toLowerCase());
            if (mapped) {
                resolved.add(mapped);
            }
            for (const key of new Set([normalized, normalizeIdSegment(candidate)])) {
                const indexed = this.identifierToNativeIds.get(key);
                if (indexed) {
                    for (const nativeId of indexed) {
                        resolved.add(nativeId);
                    }
                }
            }
        }

        return Array.from(resolved);
    }

    private async dispatchMotionEvent(nativeId: string, event: SimplisafeRealtimeEvent): Promise<void> {
        try {
            const device = this.devices.get(nativeId) ?? await this.getDevice(nativeId);
            device.handleMotionEvent(event);
        } catch (err) {
            this.console.warn(`SimpliSafe motion event dispatch failed for ${nativeId}.`, err);
        }
    }

    private handleDoorbellPressEvent(event: SimplisafeRealtimeEvent): void {
        const nativeIds = this.resolveNativeIdsFromEvent(event);
        if (nativeIds.length === 0) {
            if (this.debug) {
                const identifier = event.sensorSerial
                    || event.cameraSerial
                    || event.serial
                    || event.deviceSerial
                    || event.cameraUuid
                    || event.uuid;
                this.console.warn(`SimpliSafe doorbell event could not be matched to a camera. identifier=${identifier ?? 'unknown'}`);
            }
            return;
        }

        for (const nativeId of nativeIds) {
            void this.dispatchDoorbellEvent(nativeId, event);
        }
    }

    private async dispatchDoorbellEvent(nativeId: string, event: SimplisafeRealtimeEvent): Promise<void> {
        try {
            const device = this.devices.get(nativeId) ?? await this.getDevice(nativeId);
            device.handleDoorbellEvent(event);
        } catch (err) {
            this.console.warn(`SimpliSafe doorbell event dispatch failed for ${nativeId}.`, err);
        }
    }

    private async startRealtimeEvents(): Promise<void> {
        if (!this.authManager.hasRefreshToken()) {
            return;
        }
        try {
            await this.api.startListening();
        } catch (err) {
            if (this.debug) {
                this.console.warn('SimpliSafe realtime events unavailable.', err);
            }
        }
    }

    private scheduleRefreshDescriptor(nativeId: string, delayMs = 500): void {
        const normalized = this.normalizeNativeId(nativeId);
        const existingTimer = this.publishTimers.get(normalized);
        if (existingTimer) {
            clearTimeout(existingTimer);
        }

        const timer = setTimeout(() => {
            this.publishTimers.delete(normalized);
            this.refreshDeviceDescriptor(normalized).catch(err => {
                this.console.warn(`Failed to refresh descriptor for ${normalized}.`, err);
            });
        }, delayMs);

        this.publishTimers.set(normalized, timer);
    }

    private async publishCameraMeta(nativeId: string, meta: {
        name: string;
        type: ScryptedDeviceType;
        interfaces: (ScryptedInterface | string)[];
        info?: Device['info'];
    }): Promise<void> {
        const normalized = this.normalizeNativeId(nativeId);
        const interfaces = [...new Set(meta.interfaces.filter(Boolean))];
        const descriptor: Device = {
            nativeId: normalized,
            name: meta.name,
            type: meta.type,
            interfaces,
        };
        if (meta.info) {
            descriptor.info = meta.info;
        }
        const cachedDescriptor: CachedCameraDescriptor = {
            nativeId: normalized,
            name: descriptor.name,
            type: meta.type,
            interfaces: descriptor.interfaces,
            info: descriptor.info,
        };
        const key = this.computeDescriptorKey(cachedDescriptor);
        if (this.lastPublished.get(normalized) === key) {
            if (!this.cachedDescriptors.has(normalized)) {
                this.cachedDescriptors.set(normalized, cachedDescriptor);
                this.persistCachedDescriptors();
            }
            return;
        }

        // Stage the update in cachedDescriptors before publishing so that when
        // we call onDevicesChanged we include ALL known cameras in one batch.
        // onDevicesChanged replaces the plugin's entire child device list, so
        // passing only the single updated device would erase all other cameras.
        const previous = this.cachedDescriptors.get(normalized);
        this.cachedDescriptors.set(normalized, cachedDescriptor);

        const allDevices: Device[] = Array.from(this.cachedDescriptors.values()).map(d => {
            const dev: Device = {
                nativeId: d.nativeId,
                name: d.name,
                type: d.type,
                interfaces: d.interfaces,
            };
            if (d.info) dev.info = d.info;
            return dev;
        });

        try {
            await deviceManager.onDevicesChanged({ devices: allDevices });
            this.lastPublished.set(normalized, key);
            this.persistCachedDescriptors();
        } catch (err) {
            // Revert the staged update so cachedDescriptors stays consistent
            if (previous) {
                this.cachedDescriptors.set(normalized, previous);
            } else {
                this.cachedDescriptors.delete(normalized);
            }
            this.console.warn(`Failed to publish SimpliSafe device descriptor for ${normalized}.`, err);
        }
    }

    private async refreshDeviceDescriptor(nativeId: string): Promise<void> {
        const details = this.cameraDetails.get(nativeId);
        if (!details) {
            return;
        }

        const liveKit = isLiveKitCameraDetails(details);
        const doorbell = isDoorbellCamera(details);
        const interfaces: (ScryptedInterface | string)[] = [
            ScryptedInterface.Camera,
            ScryptedInterface.Settings,
            RESOLUTION_INTERFACE,
            ScryptedInterface.Online,
            ScryptedInterface.MotionSensor,
        ];

        // Legacy cameras always advertise VideoCamera, without waiting for the readiness probe.
        // LiveKit cameras stream over WebRTC (RTCSignalingChannel) and getVideoStream throws for
        // them, so advertising VideoCamera would hand consumers a dead FLV path.
        if (!liveKit) {
            interfaces.push(ScryptedInterface.VideoCamera);
        }

        if (doorbell) {
            interfaces.push(ScryptedInterface.BinarySensor);
        }

        if (liveKit) {
            interfaces.push(ScryptedInterface.RTCSignalingChannel);
            // LiveKit cameras support two-way audio by publishing a mic track upstream.
            interfaces.push(ScryptedInterface.Intercom);
        }

        const name = details.cameraSettings?.cameraName
            || details.name
            || `Camera ${details.uuid ?? nativeId}`;

        await this.publishCameraMeta(nativeId, {
            name,
            type: doorbell ? ScryptedDeviceType.Doorbell : ScryptedDeviceType.Camera,
            interfaces,
            info: {
                manufacturer: 'SimpliSafe',
                model: details.model,
                serialNumber: details.uuid,
                firmware: details.cameraSettings?.admin?.firmwareVersion,
            },
        });
    }

    private async maintenanceCleanup(): Promise<void> {
        if (process.env.SIMPLISAFE_DEV_CLEAN !== '1') {
            return;
        }

        try {
            this.console.log('SimpliSafe maintenance: scanning Scrypted device registry.');
            const nativeIds = deviceManager.getNativeIds() || [];
            for (const nativeId of nativeIds) {
                if (!nativeId) {
                    continue;
                }
                let name: string | undefined;
                let id: string | undefined;
                let hasDeviceState = false;
                try {
                    const state = deviceManager.getDeviceState(nativeId);
                    if (state && (state as any)._id) {
                        id = (state as any)._id;
                        name = (state as any).name;
                    }
                    if (state) {
                        hasDeviceState = true;
                    }
                } catch (err) {
                    this.console.warn(`SimpliSafe maintenance: failed to retrieve state for nativeId ${nativeId}.`, err);
                }

                this.console.log(`SimpliSafe maintenance: device nativeId=${nativeId} id=${id ?? 'unknown'} name=${name ?? 'unknown'}`);

                if (!nativeId?.startsWith('simplisafe-')) {
                    continue;
                }

                if (this.currentNativeIds.has(this.normalizeNativeId(nativeId))) {
                    continue;
                }

                if (!id) {
                    if (this.debug) {
                        this.console.log(`SimpliSafe maintenance: skipping removal of ${nativeId}, no Scrypted id found.`);
                    }
                    continue;
                }

                if (this.debug) {
                    this.console.log(`SimpliSafe maintenance: removing stale SimpliSafe device ${nativeId} (id ${id}).`);
                }

                try {
                    const existingState = hasDeviceState ? true : !!deviceManager.getDeviceState(nativeId);
                    if (existingState) {
                        await deviceManager.onDeviceRemoved(nativeId);
                    }
                } catch (err) {
                    this.console.warn(`SimpliSafe maintenance: failed to remove stale device ${nativeId}.`, err);
                }
            }
        } catch (err) {
            this.console.warn('SimpliSafe maintenance: cleanup encountered an error.', err);
        }
    }

    private dumpSystemStateOnce(): void {
        if (this.hasDumpedSystemState) {
            return;
        }

        this.hasDumpedSystemState = true;
        try {
            const state = systemManager.getSystemState();
            this.console.log('SimpliSafe system state snapshot:');
            for (const [id, deviceState] of Object.entries(state ?? {})) {
                const name = (deviceState as any)?.name?.value ?? 'unknown';
                const nativeId = (deviceState as any)?.nativeId?.value ?? 'unknown';
                const pluginId = (deviceState as any)?.pluginId?.value ?? 'unknown';
                const interfaces = (deviceState as any)?.interfaces?.value;
                const interfacesText = Array.isArray(interfaces) ? interfaces.join(', ') : interfaces ?? 'unknown';
                this.console.log(`  id=${id} name=${name} nativeId=${nativeId} pluginId=${pluginId} interfaces=${interfacesText}`);
            }
        } catch (err) {
            this.console.warn('SimpliSafe system state snapshot failed.', err);
        }
    }

    private handleCameraDetailsUpdate(nativeId: string, details: SimplisafeCameraDetails): void {
        const normalized = this.normalizeNativeId(nativeId);
        const previousUuid = this.nativeIdToUuid.get(normalized);
        if (previousUuid && previousUuid !== details.uuid) {
            this.removeUuidAssociation(previousUuid);
        }

        this.cameraDetails.set(normalized, details);
        this.registerCameraIdentifiers(normalized, details);
        this.pendingRemoval.delete(normalized);

        if (details.uuid) {
            this.nativeIdToUuid.set(normalized, details.uuid);
            this.associateUuidWithNativeId(details.uuid, normalized);
        } else {
            this.nativeIdToUuid.delete(normalized);
        }

        const desiredOnline = details.status ? details.status === 'online' : true;
        this.cameraDesiredOnline.set(normalized, desiredOnline);

        if (!this.cameraReady.has(normalized)) {
            this.cameraReady.set(normalized, false);
        }

        if (!this.syncing) {
            this.scheduleRefreshDescriptor(normalized);
        }

        this.schedulePersistCameraDetails();
    }

    private updateCameraStatus(nativeId: string, ready: boolean, desiredOnline: boolean): void {
        const normalized = this.normalizeNativeId(nativeId);
        const previousReady = this.cameraReady.get(normalized);
        this.cameraReady.set(normalized, ready);
        this.cameraDesiredOnline.set(normalized, desiredOnline);

        if (!this.syncing && previousReady !== ready && !this.upgradedNativeIds.has(normalized)) {
            this.scheduleRefreshDescriptor(normalized);
        }

        const online = ready && desiredOnline;
        const previous = this.cameraLastOnline.get(normalized);
        if (previous !== online) {
            this.cameraLastOnline.set(normalized, online);
            deviceManager.onDeviceEvent(normalized, ScryptedInterface.Online, online).catch(err => {
                this.console.warn(`Failed to report online status for ${normalized}.`, err);
            });
        }
    }

    private scheduleReadinessEvaluation(nativeId: string, delayMs = 0): void {
        const normalized = this.normalizeNativeId(nativeId);
        if (this.upgradedNativeIds.has(normalized)) {
            return;
        }
        if (this.readinessTasks.has(normalized)) {
            return;
        }

        const task = this.runReadinessEvaluation(normalized, delayMs).finally(() => {
            this.readinessTasks.delete(normalized);
        });
        this.readinessTasks.set(normalized, task);
    }

    private async runReadinessEvaluation(nativeId: string, delayMs: number): Promise<void> {
        if (delayMs > 0) {
            await sleep(delayMs);
        }

        let device: SimplisafeCamera | undefined;
        try {
            device = await this.getDevice(nativeId);
        } catch (err) {
            this.console.warn(`SimpliSafe readiness: failed to obtain device ${nativeId} for upgrade.`, err);
            return;
        }

        if (device.isStreamingReady()) {
            return;
        }

        const ready = await device.prepareForStreaming();
        if (ready) {
            await this.publishCameraUpgrade(nativeId, device);
        } else {
            this.console.warn(`SimpliSafe readiness: probe failed for ${nativeId}, retrying in ${readinessRetryInterval / 1000}s.`);
            this.scheduleReadinessEvaluation(nativeId, readinessRetryInterval);
        }
    }

    private async publishCameraUpgrade(nativeId: string, device: SimplisafeCamera): Promise<void> {
        const normalized = this.normalizeNativeId(nativeId);
        if (this.upgradedNativeIds.has(normalized)) {
            return;
        }
        const details = this.cameraDetails.get(normalized);
        if (!details) {
            this.console.warn(`SimpliSafe readiness: missing details for ${normalized}, skipping upgrade.`);
            return;
        }

        this.upgradedNativeIds.add(normalized);
        this.persistCameraReadiness();
        device.markReady();
        await this.refreshDeviceDescriptor(normalized);
        // VideoCamera is advertised unconditionally for legacy cameras now, so this probe only
        // gates the Online state, not the interface list.
        this.console.log(`SimpliSafe readiness: ${normalized} passed the streaming probe.`);
    }

    private async initialize(): Promise<void> {
        if (!this.authManager.hasRefreshToken()) {
            this.console.log('SimpliSafe plugin waiting for authentication. Configure credentials in the settings.');
            return;
        }

        try {
            this.console.log('SimpliSafe plugin initialization: syncing devices.');
            await this.syncDevices();
            await this.startRealtimeEvents();
            this.console.log('SimpliSafe plugin initialization completed.');
        } catch (err) {
            this.console.error('Failed to initialize SimpliSafe cameras.', err);
        }
    }

    private loadCachedCameras(): void {
        const cached = this.storage.getItem('cameras');
        if (!cached) {
            return;
        }

        try {
            const parsed: SimplisafeCameraDetails[] = JSON.parse(cached);
            for (const camera of parsed) {
                if (!camera) {
                    continue;
                }
                const nativeId = this.normalizeNativeId(deriveCameraNativeId(camera));
                if (this.cameraDetails.has(nativeId) && this.debug) {
                    this.console.warn(`Duplicate cached SimpliSafe camera nativeId detected: ${nativeId}. Overwriting existing entry.`);
                }
                this.cameraDetails.set(nativeId, camera);
                this.registerCameraIdentifiers(nativeId, camera);
                if (camera.uuid) {
                    this.nativeIdToUuid.set(nativeId, camera.uuid);
                    this.associateUuidWithNativeId(camera.uuid, nativeId);
                }
            }
        } catch (err) {
            this.console.warn('Failed to load cached camera data.', err);
        }
    }

    private loadCameraReadiness(): void {
        const stored = this.storage.getItem(this.readinessStorageKey);
        if (!stored) {
            return;
        }

        try {
            const parsed = JSON.parse(stored) as unknown;
            const readyIds: string[] = Array.isArray(parsed)
                ? parsed.filter((id): id is string => typeof id === 'string' && id.trim().length > 0)
                : parsed && typeof parsed === 'object'
                    ? Object.entries(parsed as Record<string, unknown>)
                        .filter(([, value]) => value === true)
                        .map(([id]) => id)
                    : [];

            for (const id of readyIds) {
                const normalized = this.normalizeNativeId(id);
                this.upgradedNativeIds.add(normalized);
                this.cameraReady.set(normalized, true);
            }
        } catch (err) {
            this.console.warn('Failed to load SimpliSafe camera readiness state.', err);
        }
    }

    private persistCameraReadiness(): void {
        try {
            const ready = Array.from(this.upgradedNativeIds);
            if (ready.length > 0) {
                this.storage.setItem(this.readinessStorageKey, JSON.stringify(ready));
            } else {
                this.storage.removeItem(this.readinessStorageKey);
            }
        } catch (err) {
            this.console.warn('Failed to persist SimpliSafe camera readiness state.', err);
        }
    }

    private loadCachedDescriptors(): void {
        const cached = this.storage.getItem('cameraDescriptors');
        if (!cached) {
            return;
        }

        try {
            const parsed = JSON.parse(cached) as CachedCameraDescriptor[];
            if (!Array.isArray(parsed)) {
                return;
            }

            for (const descriptor of parsed) {
                if (!descriptor?.nativeId || !descriptor?.name || !descriptor?.type || !Array.isArray(descriptor.interfaces)) {
                    continue;
                }
                const normalized = this.normalizeNativeId(descriptor.nativeId);
                const stored: CachedCameraDescriptor = {
                    nativeId: normalized,
                    name: descriptor.name,
                    type: descriptor.type,
                    interfaces: [...new Set(descriptor.interfaces.filter(Boolean))],
                    info: descriptor.info,
                };
                this.cachedDescriptors.set(normalized, stored);
                const key = this.computeDescriptorKey(stored);
                this.lastPublished.set(normalized, key);
                const streamingReady = stored.interfaces.includes(ScryptedInterface.VideoCamera)
                    || stored.interfaces.includes('VideoCamera')
                    || stored.interfaces.includes(ScryptedInterface.RTCSignalingChannel)
                    || stored.interfaces.includes('RTCSignalingChannel');
                if (streamingReady) {
                    this.upgradedNativeIds.add(normalized);
                    if (!this.cameraReady.has(normalized)) {
                        this.cameraReady.set(normalized, true);
                    }
                }
            }
        } catch (err) {
            this.console.warn('Failed to load cached SimpliSafe device descriptors.', err);
        }
    }

    private async republishCachedDescriptors(): Promise<void> {
        if (this.cachedDescriptors.size === 0) {
            return;
        }

        const devices: Device[] = [];
        for (const descriptor of this.cachedDescriptors.values()) {
            const details = this.cameraDetails.get(descriptor.nativeId);
            const doorbell = details ? isDoorbellCamera(details) : descriptor.type === ScryptedDeviceType.Doorbell;
            const correctedType = doorbell ? ScryptedDeviceType.Doorbell : ScryptedDeviceType.Camera;

            // Cached descriptors are republished before the first sync, so cameraDetails is
            // usually still empty here; fall back to the persisted interface list to tell
            // LiveKit cameras apart.
            const liveKit = details
                ? isLiveKitCameraDetails(details)
                : descriptor.interfaces.some(i => i === ScryptedInterface.RTCSignalingChannel || i === 'RTCSignalingChannel');

            let interfaces = descriptor.interfaces;

            // Legacy cameras always advertise VideoCamera; LiveKit cameras must never do so,
            // since getVideoStream throws for them and only the WebRTC path works.
            const hasVideoCamera = interfaces.some(i => i === ScryptedInterface.VideoCamera || i === 'VideoCamera');
            if (!liveKit && !hasVideoCamera) {
                interfaces = [...interfaces, ScryptedInterface.VideoCamera];
            } else if (liveKit && hasVideoCamera) {
                interfaces = interfaces.filter(i => i !== ScryptedInterface.VideoCamera && i !== 'VideoCamera');
            }

            // Always ensure BinarySensor is consistent with doorbell status regardless
            // of whether the type changed — a cached descriptor could have type=Doorbell
            // but be missing BinarySensor if it was persisted before BinarySensor was added.
            const hasBinarySensor = interfaces.some(i => i === ScryptedInterface.BinarySensor || i === 'BinarySensor');
            if (doorbell && !hasBinarySensor) {
                interfaces = [...interfaces, ScryptedInterface.BinarySensor];
            } else if (!doorbell && hasBinarySensor) {
                interfaces = interfaces.filter(i => i !== ScryptedInterface.BinarySensor && i !== 'BinarySensor');
            }

            devices.push({
                nativeId: descriptor.nativeId,
                name: descriptor.name,
                type: correctedType,
                interfaces,
                info: descriptor.info,
            });
        }

        try {
            await deviceManager.onDevicesChanged({ devices });
        } catch (err) {
            this.console.warn('Failed to republish cached SimpliSafe devices.', err);
        }
    }

    private persistCachedDescriptors(): void {
        try {
            if (this.cachedDescriptors.size === 0) {
                this.storage.removeItem('cameraDescriptors');
                return;
            }
            const payload = Array.from(this.cachedDescriptors.values());
            this.storage.setItem('cameraDescriptors', JSON.stringify(payload));
        } catch (err) {
            this.console.warn('Failed to persist cached SimpliSafe descriptors.', err);
        }
    }

    private computeDescriptorKey(descriptor: CachedCameraDescriptor): string {
        const sortedInterfaces = [...descriptor.interfaces].sort();
        return JSON.stringify({
            name: descriptor.name,
            type: descriptor.type,
            interfaces: sortedInterfaces,
            info: descriptor.info ?? null,
        });
    }

    private persistCameraDetails(): void {
        try {
            if (this.cameraDetails.size === 0) {
                this.storage.removeItem('cameras');
                return;
            }
            const details = Array.from(this.cameraDetails.values());
            this.storage.setItem('cameras', JSON.stringify(details));
        } catch (err) {
            this.console.warn('Failed to persist SimpliSafe camera details.', err);
        }
    }

    private schedulePersistCameraDetails(): void {
        if (this.persistCameraDetailsTimer) {
            return;
        }

        this.persistCameraDetailsTimer = setTimeout(() => {
            this.persistCameraDetailsTimer = undefined;
            this.persistCameraDetails();
        }, 500);
    }

    async getDevice(nativeId: string): Promise<SimplisafeCamera> {
        const normalized = this.normalizeNativeId(nativeId);
        const existing = this.devices.get(normalized);
        if (existing) {
            this.console.log(`getDevice returning cached device for ${normalized}`);
            return existing;
        }

        // Scrypted can request the same device concurrently. createDevice awaits (initialize/sync)
        // between the cache check and construction, so without memoization both callers would
        // construct and the duplicate-instance guard would throw for the loser.
        let creation = this.deviceCreations.get(normalized);
        if (!creation) {
            creation = this.createDevice(nativeId, normalized).finally(() => {
                this.deviceCreations.delete(normalized);
            });
            this.deviceCreations.set(normalized, creation);
        }
        return creation;
    }

    private async createDevice(nativeId: string, normalized: string): Promise<SimplisafeCamera> {
        let lookupNativeId = normalized;

        if (!this.cameraDetails.has(lookupNativeId)) {
            const migratedNativeId = this.uuidToNativeId.get(nativeId);
            if (migratedNativeId && this.normalizeNativeId(migratedNativeId) !== lookupNativeId) {
                const stable = this.normalizeNativeId(migratedNativeId);
                this.console.warn(`Legacy SimpliSafe nativeId ${nativeId} requested. Redirecting to stable nativeId ${stable}.`);
                lookupNativeId = stable;
            }
        }

        if (!this.cameraDetails.has(lookupNativeId)) {
            if (this.initializing) {
                await this.initializing.catch(() => undefined);
            }
            if (!this.cameraDetails.has(lookupNativeId)) {
                try {
                    if (this.debug) {
                        this.console.log(`Camera ${lookupNativeId} not found in cache. Triggering sync.`);
                    }
                    await this.syncDevices();
                } catch (err) {
                    this.console.warn(`SimpliSafe camera ${lookupNativeId} could not be refreshed during device retrieval. Falling back to cached details.`, err);
                }
            }
        }

        // A concurrent caller may have created this device under an alias while we awaited (the
        // memoization above only dedupes identical requested ids, and legacy ids redirect here).
        // Everything from this check to construction is synchronous, so this closes the race.
        const concurrentlyCreated = this.devices.get(lookupNativeId);
        if (concurrentlyCreated) {
            return concurrentlyCreated;
        }

        let details = this.cameraDetails.get(lookupNativeId);
        let simplisafeUuid = this.nativeIdToUuid.get(lookupNativeId);

        if (!details) {
            details = buildPlaceholderCameraDetails(lookupNativeId, undefined, undefined, simplisafeUuid);
            this.cameraDetails.set(lookupNativeId, details);
            this.registerCameraIdentifiers(lookupNativeId, details);
            if (!simplisafeUuid && details.uuid) {
                simplisafeUuid = details.uuid;
                this.nativeIdToUuid.set(lookupNativeId, simplisafeUuid);
                this.associateUuidWithNativeId(simplisafeUuid, lookupNativeId);
            }
            this.console.warn(`SimpliSafe camera ${lookupNativeId} is missing metadata. Initializing with placeholder configuration.`);
        } else if (!simplisafeUuid && details.uuid) {
            simplisafeUuid = details.uuid;
            this.nativeIdToUuid.set(lookupNativeId, simplisafeUuid);
            this.associateUuidWithNativeId(simplisafeUuid, lookupNativeId);
        }

        const device = new SimplisafeCamera(
            lookupNativeId,
            simplisafeUuid,
            this.api,
            this.authManager,
            () => this.debug,
            updated => this.handleCameraDetailsUpdate(lookupNativeId, updated),
            (ready, desiredOnline) => this.updateCameraStatus(lookupNativeId, ready, desiredOnline),
        );
        if (!this.cameraReady.has(lookupNativeId)) {
            this.cameraReady.set(lookupNativeId, false);
        }
        this.devices.set(lookupNativeId, device);
        device.updateDetails(details);
        if (this.upgradedNativeIds.has(lookupNativeId)) {
            device.markReady();
        }
        this.console.log(`Created new SimplisafeCamera device for ${lookupNativeId}`);
        return device;
    }

    async releaseDevice(id: string, nativeId: string): Promise<void> {
        const normalized = this.normalizeNativeId(nativeId);
        const device = this.devices.get(normalized);
        if (device) {
            device.dispose();
        }
        this.devices.delete(normalized);
        const timer = this.publishTimers.get(normalized);
        if (timer) {
            clearTimeout(timer);
            this.publishTimers.delete(normalized);
        }
        this.lastPublished.delete(normalized);
        this.readinessTasks.delete(normalized);
        // Do NOT delete from cachedDescriptors or persist here — Scrypted calls
        // releaseDevice sequentially during shutdown, so persisting mid-shutdown
        // would write a partial descriptor list and cause missing cameras on next boot.
        this.pendingRemoval.delete(normalized);
        this.schedulePersistCameraDetails();
    }

    async getSettings(): Promise<Setting[]> {
        const status = this.authManager.hasRefreshToken()
            ? (this.authManager.isAuthenticated() ? 'Authenticated' : 'Refresh token stored, awaiting refresh')
            : 'Not authenticated';

        return [
            {
                key: 'loginUrl',
                title: 'Login URL',
                description: 'Open this URL to authenticate with SimpliSafe. Paste the final redirect URL below.',
                value: this.authManager.getSSAuthURL(),
                readonly: true,
            },
            {
                key: 'authorizationCode',
                title: 'Authorization Redirect URL',
                description: 'After completing login, paste the entire redirect URL here to link your account.',
                placeholder: 'com.simplisafe.mobile://auth...?',
            },
            {
                key: 'refreshToken',
                title: 'Refresh Token',
                description: 'Optional: manually provide a refresh token obtained from another client.',
                value: this.authManager.refreshToken,
            },
            {
                key: 'accountNumber',
                title: 'Account Number',
                description: 'Required only if your SimpliSafe account has multiple monitoring plans.',
                value: this.accountNumber,
            },
            {
                key: 'debug',
                title: 'Debug Logging',
                description: 'Enable verbose logging for troubleshooting.',
                type: 'boolean',
                value: this.debug,
            },
            {
                key: 'status',
                title: 'Authentication Status',
                readonly: true,
                value: status,
            },
        ];
    }

    async putSetting(key: string, value: SettingValue): Promise<void> {
        switch (key) {
        case 'authorizationCode':
            if (typeof value === 'string' && value.trim()) {
                await this.handleAuthorization(value.trim());
            }
            break;
        case 'refreshToken':
            if (typeof value === 'string' && value.trim()) {
                this.authManager.setRefreshToken(value.trim());
                this.storage.setItem('refreshToken', value.trim());
                try {
                    await this.authManager.refreshCredentials();
                } catch (err) {
                    this.console.error('Failed to refresh credentials with provided refresh token.', err);
                    throw err;
                }
            } else {
                this.authManager.setRefreshToken(undefined);
                this.storage.removeItem('refreshToken');
            }
            await this.syncDevices(true);
            break;
        case 'accountNumber':
            if (typeof value === 'string' && value.trim()) {
                this.accountNumber = value.trim();
                this.storage.setItem('accountNumber', this.accountNumber);
            } else {
                this.accountNumber = undefined;
                this.storage.removeItem('accountNumber');
            }
            this.api.setAccountNumber(this.accountNumber);
            await this.syncDevices(true);
            break;
        case 'debug':
            {
                const debugEnabled = value === true || value === 'true';
                this.debug = debugEnabled;
                this.storage.setItem('debug', debugEnabled ? 'true' : 'false');
                this.authManager.setDebug(debugEnabled);
                this.api.setDebug(debugEnabled);
                break;
            }
        default:
            break;
        }
    }

    private async handleAuthorization(redirectUrl: string): Promise<void> {
        const accessToken = await this.authManager.getToken(redirectUrl);
        if (!accessToken) {
            throw new Error('SimpliSafe did not return an access token.');
        }
        await this.authManager.refreshCredentials();
        await this.syncDevices(true);
        await this.startRealtimeEvents();
    }

    private async syncDevices(forceRefresh = false): Promise<void> {
        if (!this.authManager.hasRefreshToken()) {
            return;
        }

        this.syncing = true;
        try {
            const cameras = await this.api.getCameras(forceRefresh);
            if (cameras.length === 0 && this.cameraDetails.size > 0 && !forceRefresh) {
                this.console.warn('SimpliSafe API returned zero cameras; retaining cached camera list to avoid device removal.');
                return;
            }

            if (this.debug) {
                this.console.log(`syncDevices received ${cameras.length} cameras from API.`);
            }

            let readinessChanged = false;
            this.currentNativeIds.clear();
            const existing = new Set(this.cameraDetails.keys());

            for (const camera of cameras) {
                const derivedNativeId = deriveCameraNativeId(camera);
                const nativeId = this.normalizeNativeId(derivedNativeId);
                existing.delete(nativeId);
                this.currentNativeIds.add(nativeId);
                this.handleCameraDetailsUpdate(nativeId, camera);
                if (!this.cameraReady.has(nativeId)) {
                    this.cameraReady.set(nativeId, false);
                }
                this.scheduleRefreshDescriptor(nativeId, 0);
            }

            this.storage.setItem('cameras', JSON.stringify(cameras));
            const registeredIds = cameras.map(camera => {
                const nativeId = this.normalizeNativeId(deriveCameraNativeId(camera));
                const uuid = this.nativeIdToUuid.get(nativeId);
                return uuid ? `${nativeId} (uuid: ${uuid})` : nativeId;
            });
            this.console.log(`SimpliSafe onDevicesChanged registering: ${registeredIds.length ? registeredIds.join(', ') : 'none'}.`);

            this.dumpSystemStateOnce();

            for (const [id, device] of this.devices) {
                const details = this.cameraDetails.get(id);
                if (details) {
                    device.updateDetails(details);
                }
            }

            for (const nativeId of this.currentNativeIds) {
                const ready = this.cameraReady.get(nativeId) ?? false;
                const desired = this.cameraDesiredOnline.get(nativeId) ?? true;
                const online = ready && desired;
                const previous = this.cameraLastOnline.get(nativeId);
                if (previous !== online) {
                    this.cameraLastOnline.set(nativeId, online);
                    deviceManager.onDeviceEvent(nativeId, ScryptedInterface.Online, online).catch(err => {
                        this.console.warn(`Failed to report online status for ${nativeId}.`, err);
                    });
                }
            }

            const now = Date.now();
            for (const legacy of existing) {
                const missingSince = this.pendingRemoval.get(legacy);
                if (!forceRefresh) {
                    if (!missingSince) {
                        this.pendingRemoval.set(legacy, now);
                        if (this.debug) {
                            this.console.log(`SimpliSafe camera ${legacy} missing from discovery; awaiting confirmation before removal.`);
                        }
                    }
                    this.scheduleRemovalRecheck();
                    continue;
                }

                if (!missingSince) {
                    this.pendingRemoval.set(legacy, now);
                    this.scheduleRemovalRecheck();
                    continue;
                }

                this.pendingRemoval.delete(legacy);
                const uuid = this.nativeIdToUuid.get(legacy);
                if (uuid) {
                    this.removeUuidAssociation(uuid);
                }
                this.nativeIdToUuid.delete(legacy);
                this.cameraDetails.delete(legacy);
                this.unregisterCameraIdentifiers(legacy);
                this.cameraReady.delete(legacy);
                this.cameraDesiredOnline.delete(legacy);
                this.cameraLastOnline.delete(legacy);
                if (this.upgradedNativeIds.delete(legacy)) {
                    readinessChanged = true;
                }
                this.readinessTasks.delete(legacy);
                const timer = this.publishTimers.get(legacy);
                if (timer) {
                    clearTimeout(timer);
                    this.publishTimers.delete(legacy);
                }
                this.lastPublished.delete(legacy);
                const device = this.devices.get(legacy);
                if (device) {
                    device.dispose();
                }
                this.devices.delete(legacy);
                this.cachedDescriptors.delete(legacy);
                try {
                    const state = deviceManager.getDeviceState(legacy);
                    if (state) {
                        await deviceManager.onDeviceRemoved(legacy);
                    }
                } catch (err) {
                    this.console.warn(`Failed to remove legacy SimpliSafe nativeId ${legacy}.`, err);
                }
                this.persistCachedDescriptors();
                this.schedulePersistCameraDetails();
            }

            for (const nativeId of this.cameraDetails.keys()) {
                this.scheduleReadinessEvaluation(nativeId);
            }

            if (readinessChanged) {
                this.persistCameraReadiness();
            }

            await this.startRealtimeEvents();
        } catch (err) {
            this.console.error('Failed to refresh SimpliSafe cameras.', err);
            throw err;
        } finally {
            this.syncing = false;
        }
    }

    private scheduleRemovalRecheck(delayMs = 60_000): void {
        if (this.pendingRemovalTimer) {
            return;
        }

        this.pendingRemovalTimer = setTimeout(() => {
            this.pendingRemovalTimer = undefined;
            this.syncDevices(true).catch(err => {
                this.console.warn('SimpliSafe removal confirmation sync failed.', err);
            });
        }, delayMs);
    }
}

export default SimplisafePlugin;
