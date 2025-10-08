import sdk, {
    Camera,
    Device,
    DeviceProvider,
    FFmpegInput,
    MediaObject,
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

const { deviceManager, mediaManager } = sdk;

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

const ssOAuth: AxiosInstance = axios.create({
    baseURL: 'https://auth.simplisafe.com/oauth',
});
axiosRetry(ssOAuth, { retries: 3 });

export const AUTH_EVENTS = {
    REFRESH_CREDENTIALS_SUCCESS: 'REFRESH_CREDENTIALS_SUCCESS',
    REFRESH_CREDENTIALS_FAILURE: 'REFRESH_CREDENTIALS_FAILURE',
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

class SimplisafeApi {
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

    constructor(authManager: SimplisafeAuthManager, log: Console, debug: boolean) {
        this.authManager = authManager;
        this.log = log;
        this.debug = debug;
        this.axios = axios.create({
            baseURL: 'https://api.simplisafe.com/v1',
        });
        axiosRetry(this.axios, { retries: 2 });
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
            return this.cameraCache.data;
        }

        const system = await this.getAlarmSystem(forceRefresh);
        const cameras: SimplisafeCameraDetails[] = system?.cameras ?? [];
        this.cameraCache = {
            data: cameras,
            timestamp: Date.now(),
        };
        return cameras;
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

class SimplisafeCamera extends ScryptedDeviceBase implements Camera, VideoCamera {
    private readonly api: SimplisafeApi;
    private readonly authManager: SimplisafeAuthManager;
    private readonly getDebug: DebugProvider;
    private details?: SimplisafeCameraDetails;
    private streamOptions?: ResponseMediaStreamOptions[];
    private pictureOptions?: ResponsePictureOptions[];
    private mediaHost?: string;
    private mediaHostTimestamp = 0;

    constructor(nativeId: string, api: SimplisafeApi, authManager: SimplisafeAuthManager, getDebug: DebugProvider) {
        super(nativeId);
        this.api = api;
        this.authManager = authManager;
        this.getDebug = getDebug;
    }

    updateDetails(details: SimplisafeCameraDetails): void {
        this.details = details;
        this.streamOptions = undefined;
        this.pictureOptions = undefined;
        const name = this.getCameraName(details);
        this.name = name;
        this.info = {
            manufacturer: 'SimpliSafe',
            model: details.model,
            serialNumber: details.uuid,
            firmware: details.cameraSettings?.admin?.firmwareVersion,
        };
        this.online = details.status === 'online';
    }

    async getVideoStreamOptions(): Promise<ResponseMediaStreamOptions[]> {
        if (!this.details) {
            throw new Error('Camera details are unavailable.');
        }

        if (!this.streamOptions) {
            this.streamOptions = this.buildStreamOptions(this.details);
        }

        return this.streamOptions;
    }

    async getVideoStream(options?: RequestMediaStreamOptions): Promise<MediaObject> {
        if (!this.details) {
            throw new Error('Camera details are unavailable.');
        }

        if (this.isUnsupported(this.details)) {
            throw new Error(`${this.name} does not support SimpliSafe cloud streaming.`);
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
        const url = `https://${host}/v1/${this.details.uuid}/flv?x=${width}&audioEncoding=AAC`;
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

        if (this.getDebug()) {
            this.console.log(`${this.name} streaming via ${url}`);
        }

        return mediaManager.createFFmpegMediaObject(ffmpegInput);
    }

    async takePicture(options?: RequestPictureOptions): Promise<MediaObject> {
        if (!this.details) {
            throw new Error('Camera details are unavailable.');
        }

        if (this.isUnsupported(this.details)) {
            throw new Error(`${this.name} does not support snapshots.`);
        }

        const streamOptions = await this.getVideoStreamOptions();
        const preferred = streamOptions[streamOptions.length - 1];
        const width = options?.picture?.width
            ?? preferred.video?.width
            ?? 1920;

        const accessToken = await this.api.getAccessToken();
        const host = await this.getMediaHost();
        const snapshotUrl = `https://${host}/v1/${this.details.uuid}/mjpg?x=${width}&fr=1`;

        const image = await jpegExtract({
            url: snapshotUrl,
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
            rejectUnauthorized: false,
        });

        return this.createMediaObject(image, 'image/jpeg');
    }

    async getPictureOptions(): Promise<ResponsePictureOptions[]> {
        if (!this.details) {
            throw new Error('Camera details are unavailable.');
        }

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
            source: 'cloud',
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
                    throw err;
                }
                this.console.warn('Unable to resolve media.simplisafe.com, using cached IP address.', err);
            }
        }

        return this.mediaHost!;
    }

    private getCameraName(details: SimplisafeCameraDetails): string {
        return details.cameraSettings?.cameraName || details.name || `Camera ${details.uuid}`;
    }

    private isUnsupported(details: SimplisafeCameraDetails): boolean {
        return details.supportedFeatures?.providers?.recording !== undefined
            && details.supportedFeatures.providers.recording !== 'simplisafe';
    }
}

class SimplisafePlugin extends ScryptedDeviceBase implements DeviceProvider, Settings {
    private readonly devices = new Map<string, SimplisafeCamera>();
    private readonly cameraDetails = new Map<string, SimplisafeCameraDetails>();
    private readonly authManager: SimplisafeAuthManager;
    private readonly api: SimplisafeApi;
    private debug: boolean;
    private accountNumber?: string;
    private initializing?: Promise<void>;

    constructor() {
        super();
        this.debug = this.storage.getItem('debug') === 'true';
        const storedAccount = this.storage.getItem('accountNumber');
        this.accountNumber = storedAccount || undefined;

        this.authManager = new SimplisafeAuthManager(this.storage, this.console, this.debug);
        this.api = new SimplisafeApi(this.authManager, this.console, this.debug);
        this.api.setAccountNumber(this.accountNumber);

        this.loadCachedCameras();
        this.initializing = this.initialize();
    }

    private async initialize(): Promise<void> {
        if (!this.authManager.hasRefreshToken()) {
            this.console.log('SimpliSafe plugin waiting for authentication. Configure credentials in the settings.');
            return;
        }

        try {
            await this.syncDevices();
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
                if (camera?.uuid) {
                    this.cameraDetails.set(camera.uuid, camera);
                }
            }
        } catch (err) {
            this.console.warn('Failed to load cached camera data.', err);
        }
    }

    async getDevice(nativeId: string): Promise<SimplisafeCamera> {
        let device = this.devices.get(nativeId);
        if (device) {
            return device;
        }

        if (!this.cameraDetails.has(nativeId)) {
            if (this.initializing) {
                await this.initializing.catch(() => undefined);
            }
            if (!this.cameraDetails.has(nativeId)) {
                await this.syncDevices();
            }
        }

        const details = this.cameraDetails.get(nativeId);
        if (!details) {
            throw new Error(`Unknown SimpliSafe camera with native id ${nativeId}`);
        }

        device = new SimplisafeCamera(nativeId, this.api, this.authManager, () => this.debug);
        device.updateDetails(details);
        this.devices.set(nativeId, device);
        return device;
    }

    async releaseDevice(id: string, nativeId: string): Promise<void> {
        this.devices.delete(nativeId);
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
    }

    private async syncDevices(forceRefresh = false): Promise<void> {
        if (!this.authManager.hasRefreshToken()) {
            return;
        }

        try {
            const cameras = await this.api.getCameras(forceRefresh);
            const devices: Device[] = [];
            this.cameraDetails.clear();
            for (const camera of cameras) {
                this.cameraDetails.set(camera.uuid, camera);
                devices.push({
                    nativeId: camera.uuid,
                    name: camera.cameraSettings?.cameraName || camera.name || `Camera ${camera.uuid}`,
                    type: ScryptedDeviceType.Camera,
                    interfaces: [
                        ScryptedInterface.Camera,
                        ScryptedInterface.VideoCamera,
                    ],
                    info: {
                        manufacturer: 'SimpliSafe',
                        model: camera.model,
                        serialNumber: camera.uuid,
                        firmware: camera.cameraSettings?.admin?.firmwareVersion,
                    },
                });
            }

            this.storage.setItem('cameras', JSON.stringify(cameras));
            await deviceManager.onDevicesChanged({ devices });

            for (const [id, device] of this.devices) {
                const details = this.cameraDetails.get(id);
                if (details) {
                    device.updateDetails(details);
                }
            }
        } catch (err) {
            this.console.error('Failed to refresh SimpliSafe cameras.', err);
            throw err;
        }
    }
}

export default SimplisafePlugin;
