import sdk, {
    Camera,
    Device,
    DeviceState,
    DeviceProvider,
    FFmpegInput,
    MediaObject,
    MotionSensor,
    RequestMediaStreamOptions,
    RequestPictureOptions,
    ResponseMediaStreamOptions,
    ResponsePictureOptions,
    ScryptedDeviceBase,
    ScryptedDeviceType,
    ScryptedInterface,
    Setting,
    SettingValue,
    Settings,
    VideoCamera,
} from '@scrypted/sdk';
import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios';
import axiosRetry from 'axios-retry';
import { EventEmitter } from 'events';
import crypto from 'crypto';
import { lookup } from 'dns/promises';
import jpegExtract from 'jpeg-extract';
import WebSocket, { RawData } from 'ws';

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
const rateLimitMaxInterval = 2 * 60 * 60 * 1000;
const mediaHostTtl = 5 * 60 * 1000;
const socketRetryInterval = 1000;
const socketHeartbeatInterval = 60_000;
const socketRetryBackoffCap = 60_000;
const RESOLUTION_INTERFACE: ScryptedInterface | string = (ScryptedInterface as any).Resolution ?? 'Resolution';

const ssOAuth: AxiosInstance = axios.create({
    baseURL: 'https://auth.simplisafe.com/oauth',
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
    private isBlocked = false;
    private nextAttempt = 0;
    private nextBlockInterval = rateLimitInitialInterval;
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
            return;
        }

        switch (data.eventCid) {
        case 1170:
            this.emit(EVENT_TYPES.CAMERA_MOTION, data);
            break;
        case 1458:
            this.emit(EVENT_TYPES.DOORBELL, data);
            break;
        default:
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

    private async request<T>(config: AxiosRequestConfig): Promise<T> {
        if (this.isBlocked && Date.now() < this.nextAttempt) {
            throw new RateLimitError('Blocking request: rate limited');
        }

        const accessToken = await this.getAccessToken();

        try {
            const response = await this.axios.request<T>({
                ...config,
                headers: {
                    ...config.headers,
                    Authorization: `${this.authManager.tokenType} ${accessToken}`,
                },
            });
            this.resetRateLimit();
            return response.data;
        } catch (error) {
            const axiosError = error as AxiosError;
            if (!axiosError.response) {
                this.setRateLimit();
                throw new RateLimitError('SimpliSafe request failed: no response received.');
            }

            if (axiosError.response.status === 403) {
                this.setRateLimit();
                throw new RateLimitError('SimpliSafe rejected the request (rate limited or auth failure).');
            }

            throw axiosError.response.data ?? axiosError;
        }
    }

    private resetRateLimit(): void {
        this.isBlocked = false;
        this.nextBlockInterval = rateLimitInitialInterval;
    }

    private setRateLimit(): void {
        this.isBlocked = true;
        this.nextAttempt = Date.now() + this.nextBlockInterval;
        if (this.nextBlockInterval < rateLimitMaxInterval) {
            this.nextBlockInterval *= 2;
        }
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

class SimplisafeCamera extends ScryptedDeviceBase implements Camera, VideoCamera, Settings, MotionSensor {
    private static instanceRegistry = new Map<string, string>();
    private readonly nativeCameraId: string;
    private readonly api: SimplisafeApi;
    private readonly authManager: SimplisafeAuthManager;
    private readonly getDebug: DebugProvider;
    private readonly detailsCallback: (details: SimplisafeCameraDetails) => void;
    private readonly statusCallback: (ready: boolean, desiredOnline: boolean) => void;
    private readonly instanceId: string;
    private details?: SimplisafeCameraDetails;
    private streamOptions?: ResponseMediaStreamOptions[];
    private pictureOptions?: ResponsePictureOptions[];
    private mediaHost?: string;
    private mediaHostTimestamp = 0;
    private simplisafeUuid?: string;
    private ready = false;
    private desiredOnline = true;
    private motionResetTimer?: NodeJS.Timeout;
    private readonly motionHoldDurationMs = 5_000;
    motionDetected?: boolean;
    motionDetectedTimestamp?: number;

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
        const current = SimplisafeCamera.instanceRegistry.get(this.nativeCameraId);
        if (current === this.instanceId) {
            SimplisafeCamera.instanceRegistry.delete(this.nativeCameraId);
        }
        if (this.motionResetTimer) {
            clearTimeout(this.motionResetTimer);
            this.motionResetTimer = undefined;
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
        console.log('SS:getVideoStreamOptions', this.nativeCameraId);
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
        console.log('SS:getVideoStream', this.nativeCameraId, options);
        try {
            const details = await this.ensureDetails();

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
            const host = await this.getMediaHost();
            const url = `https://${host}/v1/${details.uuid}/flv?x=${width}&audioEncoding=AAC`;
            const inputArguments = [
                '-re',
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
        try {
            const details = await this.ensureDetails();

            if (this.isUnsupported(details)) {
                throw new Error(`${this.getDisplayName()} does not support snapshots.`);
            }

            const streamOptions = await this.getVideoStreamOptions();
            const preferred = streamOptions[streamOptions.length - 1];
            const width = options?.picture?.width
                ?? preferred.video?.width
                ?? 1920;

            const accessToken = await this.api.getAccessToken();
            const host = await this.getMediaHost();
            const snapshotUrl = `https://${host}/v1/${details.uuid}/mjpg?x=${width}&fr=1`;

            const image = await jpegExtract({
                url: snapshotUrl,
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
                rejectUnauthorized: false,
            });

            return this.createMediaObject(image, 'image/jpeg');
        } catch (err) {
            this.console.error(`Failed to capture SimpliSafe snapshot for ${this.nativeCameraId}.`, err);
            throw err;
        }
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

    private async getMediaHost(): Promise<string> {
        const now = Date.now();
        if (!this.mediaHost || now - this.mediaHostTimestamp > mediaHostTtl) {
            try {
                const result = await lookup('media.simplisafe.com');
                this.mediaHost = result.address;
                this.mediaHostTimestamp = now;
            } catch (err) {
                if (!this.mediaHost) {
                    this.console.warn('Unable to resolve media.simplisafe.com, falling back to hostname.', err);
                    this.mediaHost = 'media.simplisafe.com';
                    this.mediaHostTimestamp = now;
                } else {
                    this.console.warn('Unable to resolve media.simplisafe.com, using cached host.', err);
                }
            }
        }

        return this.mediaHost!;
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

    private isUnsupported(details: SimplisafeCameraDetails): boolean {
        return details.supportedFeatures?.providers?.recording !== undefined
            && details.supportedFeatures.providers.recording !== 'simplisafe';
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
    private readonly currentNativeIds = new Set<string>();
    private readonly readinessTasks = new Map<string, Promise<void>>();
    private readonly upgradedNativeIds = new Set<string>();
    private readonly cameraReady = new Map<string, boolean>();
    private readonly cameraDesiredOnline = new Map<string, boolean>();
    private readonly cameraLastOnline = new Map<string, boolean>();
    private readonly lastPublished = new Map<string, string>();
    private readonly publishTimers = new Map<string, NodeJS.Timeout>();
    private syncing = false;
    private hasDumpedSystemState = false;
    private readonly authManager: SimplisafeAuthManager;
    private readonly api: SimplisafeApi;
    private debug: boolean;
    private accountNumber?: string;
    private initializing?: Promise<void>;

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

        this.loadCachedCameras();
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

    private handleCameraMotionEvent(event: SimplisafeRealtimeEvent): void {
        const nativeIds = this.resolveNativeIdsFromEvent(event);
        if (nativeIds.length === 0) {
            if (this.debug) {
                const identifier = event.sensorSerial
                    || event.cameraSerial
                    || event.serial
                    || event.deviceSerial
                    || event.cameraUuid
                    || event.uuid;
                this.console.warn(`SimpliSafe motion event could not be matched to a camera. identifier=${identifier ?? 'unknown'}`);
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
            const normalized = this.normalizeNativeId(candidate);
            if (this.cameraDetails.has(normalized)) {
                resolved.add(normalized);
            }
            const mapped = this.uuidToNativeId.get(candidate) ?? this.uuidToNativeId.get(candidate.toLowerCase());
            if (mapped) {
                resolved.add(mapped);
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
        const key = JSON.stringify({
            name: descriptor.name,
            type: descriptor.type,
            interfaces: descriptor.interfaces,
        });
        if (this.lastPublished.get(normalized) === key) {
            return;
        }
        try {
            await deviceManager.onDevicesChanged({ devices: [descriptor] });
            this.lastPublished.set(normalized, key);
        } catch (err) {
            this.console.warn(`Failed to publish SimpliSafe device descriptor for ${normalized}.`, err);
        }
    }

    private async refreshDeviceDescriptor(nativeId: string): Promise<void> {
        const details = this.cameraDetails.get(nativeId);
        if (!details) {
            return;
        }

        const includeVideoCamera = this.upgradedNativeIds.has(nativeId);
        const interfaces: (ScryptedInterface | string)[] = [
            ScryptedInterface.Camera,
            ScryptedInterface.Settings,
            RESOLUTION_INTERFACE,
            ScryptedInterface.Online,
            ScryptedInterface.MotionSensor,
        ];

        if (includeVideoCamera) {
            interfaces.push(ScryptedInterface.VideoCamera);
        }

        const name = details.cameraSettings?.cameraName
            || details.name
            || `Camera ${details.uuid ?? nativeId}`;

        await this.publishCameraMeta(nativeId, {
            name,
            type: ScryptedDeviceType.Camera,
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
        device.markReady();
        await this.refreshDeviceDescriptor(normalized);
        console.log('SS: camera now ready, advertising VideoCamera:', normalized);
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
                if (camera.uuid) {
                    this.nativeIdToUuid.set(nativeId, camera.uuid);
                    this.associateUuidWithNativeId(camera.uuid, nativeId);
                }
            }
        } catch (err) {
            this.console.warn('Failed to load cached camera data.', err);
        }
    }

    async getDevice(nativeId: string): Promise<SimplisafeCamera> {
        const normalized = this.normalizeNativeId(nativeId);
        const existing = this.devices.get(normalized);
        if (existing) {
            this.console.log(`getDevice returning cached device for ${normalized}`);
            return existing;
        }

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

        let details = this.cameraDetails.get(lookupNativeId);
        let simplisafeUuid = this.nativeIdToUuid.get(lookupNativeId);

        if (!details) {
            details = buildPlaceholderCameraDetails(lookupNativeId, undefined, undefined, simplisafeUuid);
            this.cameraDetails.set(lookupNativeId, details);
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

            for (const legacy of existing) {
                const uuid = this.nativeIdToUuid.get(legacy);
                if (uuid) {
                    this.removeUuidAssociation(uuid);
                }
                this.nativeIdToUuid.delete(legacy);
                this.cameraDetails.delete(legacy);
                this.cameraReady.delete(legacy);
                this.cameraDesiredOnline.delete(legacy);
                this.cameraLastOnline.delete(legacy);
                this.upgradedNativeIds.delete(legacy);
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
                try {
                    const state = deviceManager.getDeviceState(legacy);
                    if (state) {
                        await deviceManager.onDeviceRemoved(legacy);
                    }
                } catch (err) {
                    this.console.warn(`Failed to remove legacy SimpliSafe nativeId ${legacy}.`, err);
                }
            }

            for (const nativeId of this.cameraDetails.keys()) {
                this.scheduleReadinessEvaluation(nativeId);
            }

            await this.startRealtimeEvents();
        } catch (err) {
            this.console.error('Failed to refresh SimpliSafe cameras.', err);
            throw err;
        } finally {
            this.syncing = false;
        }
    }
}

export default SimplisafePlugin;
