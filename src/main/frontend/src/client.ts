import type { Env, Popup } from './env.ts';
import type { GatewayEvent, GatewayEventMap, GatewayListener, Options, Session, SessionUser, UnauthenticatedReason } from './types.ts';

export const MARKER_COOKIE = 'K_GATEWAY_STATE';
export const SUBJECT_HEADER = 'X-Kancelarko-Sub';
export const POPUP_DONE_PATH = '/bff/popup-done';

/** Provere na fokus, vidljivost i sl. ne češće od ovoga. */
const DEBOUNCE_MS = 3_000;
const TICK_MS = 1_000;
const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * - `starting`: prva provera još traje;
 * - `active`: prijavljen isti korisnik za koga je strana napravljena;
 * - `unauthenticated`: sesije nema, čeka se prijava (prozor) ili preusmeravanje;
 * - `user-changed`: prijavljen je neko drugi; strana mora da se osveži, zahtevi koji menjaju stanje se ne šalju;
 * - `leaving`: strana odlazi (odjava, prijava na posebnoj strani, osvežavanje).
 */
export type State = 'starting' | 'active' | 'unauthenticated' | 'user-changed' | 'leaving';

export function loginUrl(returnTo: string): string {
    return `/bff/login?returnTo=${encodeURIComponent(returnTo)}`;
}

/**
 * Prati sesiju gateway-a za stranu aplikacije:
 *
 * - cookie `K_GATEWAY_STATE` svake sekunde (bez mreže): nestao = odjava, promenjen = nova prijava;
 * - `GET /bff/session` na fokus, vidljivost taba, povratak iz bfcache-a, povratak mreže i periodično dok
 *   korisnik radi (svaki poziv produžava sesiju gateway-a, pa ne dok tab samo stoji otvoren);
 * - odgovore fetch/XHR-a aplikacije (401, 409 `user_changed`), kad je presretanje uključeno.
 */
export class GatewayClient {
    private readonly env: Env;
    private readonly options: Options;
    private state: State = 'starting';
    private session: Session | null = null;
    private expectedSub: string | null;
    private marker: string | null = null;
    private markerReason: UnauthenticatedReason | null = null;
    private lastCheck = Number.NEGATIVE_INFINITY;
    private lastActivity: number;
    private inFlight: Promise<Session | null> | null = null;
    private popup: Popup | null = null;
    private waiters: Array<(restored: boolean) => void> = [];
    private listeners = new Map<keyof GatewayEventMap, Set<GatewayListener<never>>>();
    private resolveReady!: (session: Session | null) => void;

    readonly ready: Promise<Session | null> = new Promise((resolve) => {
        this.resolveReady = resolve;
    });

    constructor(env: Env, options: Options) {
        this.env = env;
        this.options = options;
        this.expectedSub = options.expectedSub;
        this.lastActivity = env.now();
    }

    start(): void {
        const env = this.env;
        this.marker = env.readCookie(MARKER_COOKIE);

        const onReturn = () => void this.check();
        env.listen('document', 'visibilitychange', () => env.visible() && onReturn());
        env.listen('window', 'focus', onReturn);
        env.listen('window', 'pageshow', onReturn);
        env.listen('window', 'online', onReturn);
        for (const type of ['pointerdown', 'keydown', 'scroll', 'touchstart']) {
            env.listen('window', type, () => (this.lastActivity = env.now()), true);
        }
        env.listen('window', 'message', (event) => this.onMessage(event as MessageEvent));
        // Forma bez sesije ili sa tuđom sesijom bi otišla na prijavu ili pod drugim korisnikom; ostaje na strani.
        env.listen(
            'document',
            'submit',
            (event) => {
                if (this.state === 'unauthenticated' || this.state === 'user-changed') {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                }
            },
            true,
        );

        env.every(TICK_MS, () => this.tick());
        env.every(this.options.pollInterval, () => {
            if (env.visible() && env.now() - this.lastActivity < this.options.pollInterval) void this.check();
        });

        void this.check(true).then((session) => this.resolveReady(session));
    }

    getState(): State {
        return this.state;
    }

    getSession(): Session | null {
        return this.session;
    }

    getUser(): SessionUser | null {
        return this.session?.authenticated ? this.session.user : null;
    }

    /** Samo za prikaz; pristup odlučuje server po tokenu. */
    hasModule(module: string): boolean {
        const modules = this.getUser()?.modules;
        return Array.isArray(modules) && modules.includes(module);
    }

    hasRole(...roles: string[]): boolean {
        const role = this.getUser()?.role;
        return role != null && roles.includes(role);
    }

    on<K extends keyof GatewayEventMap>(type: K, listener: GatewayListener<K>): () => void {
        const set = this.listeners.get(type) ?? new Set();
        set.add(listener as GatewayListener<never>);
        this.listeners.set(type, set);
        return () => set.delete(listener as GatewayListener<never>);
    }

    /** Pita gateway; `force` preskače pauzu između provera. Mrežna greška ili 429/503 ne menjaju stanje. */
    check(force = false): Promise<Session | null> {
        if (this.inFlight) return this.inFlight;
        if (this.state === 'leaving') return Promise.resolve(this.session);
        const now = this.env.now();
        if (!force && now - this.lastCheck < DEBOUNCE_MS) return Promise.resolve(this.session);
        this.lastCheck = now;

        this.inFlight = this.fetchSession().finally(() => (this.inFlight = null));
        return this.inFlight;
    }

    login(options: { popup?: boolean; returnTo?: string } = {}): void {
        if (options.popup) {
            this.openLoginPopup();
        } else {
            this.leave(() => this.env.assign(loginUrl(options.returnTo ?? this.env.href())));
        }
    }

    logout(): void {
        this.leave(() => this.env.postLogout());
    }

    account(): void {
        this.leave(() => this.env.assign('/account'));
    }

    /** Zaglavlja za zahtev ka istom origin-u, ili `null` (tuđ origin i putanje gateway-a se ne diraju). */
    headersFor(url: string): Record<string, string> | null {
        let target: URL;
        try {
            target = new URL(url, this.env.href());
        } catch {
            return null;
        }
        if (target.origin !== this.env.origin || target.pathname.startsWith('/bff/')) return null;

        const headers: Record<string, string> = { 'X-Requested-With': 'XMLHttpRequest' };
        if (this.expectedSub) headers[SUBJECT_HEADER] = this.expectedSub;
        return headers;
    }

    /** Zahtev koji menja stanje ne sme da ode pod drugim korisnikom. */
    isBlocked(method: string): boolean {
        return this.state === 'user-changed' && UNSAFE_METHODS.has(method.toUpperCase());
    }

    /**
     * Posle odgovora aplikacije: 401 → provera sesije, pa (prozor za prijavu) čekanje na ponovnu prijavu;
     * `retry` znači da je isti korisnik ponovo prijavljen i da zahtev može ponovo.
     */
    async afterResponse(status: number, reason: () => Promise<string | null>): Promise<'retry' | 'none'> {
        if (status === 409 && (await reason()) === 'user_changed') {
            await this.check(true);
            return 'none';
        }
        if (status !== 401 || this.state === 'leaving') return 'none';

        await this.check(true);
        if (this.state !== 'unauthenticated' || this.options.onUnauthenticated !== 'dialog') return 'none';

        return (await this.waitForRestore()) ? 'retry' : 'none';
    }

    private waitForRestore(): Promise<boolean> {
        if (this.state === 'active') return Promise.resolve(true);
        return new Promise((resolve) => this.waiters.push(resolve));
    }

    private flushWaiters(restored: boolean): void {
        const waiters = this.waiters;
        this.waiters = [];
        for (const resolve of waiters) resolve(restored);
    }

    private async fetchSession(): Promise<Session | null> {
        let session: Session;
        try {
            const response = await this.env.fetch('/bff/session', {
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            });
            if (!response.ok) return this.session;
            session = (await response.json()) as Session;
        } catch {
            return this.session;
        }
        this.apply(session);

        return session;
    }

    private apply(session: Session): void {
        if (this.state === 'leaving') return;
        // Strana tuđe prijave ostaje takva dok se ne osveži, osim ako se vrati isti korisnik.
        if (this.state === 'user-changed' && !(session.authenticated && session.user?.sub === this.expectedSub)) return;
        this.session = session;

        if (!session.authenticated) {
            const reason = this.markerReason ?? session.reason ?? 'no_session';
            this.markerReason = null;
            this.unauthenticated(reason);
            return;
        }
        this.markerReason = null;

        const sub = session.user?.sub ?? null;
        if (this.expectedSub === null) this.expectedSub = sub;
        if (sub !== this.expectedSub) {
            this.userChanged(session.user);
            return;
        }

        const wasInterrupted = this.state === 'unauthenticated' || this.state === 'user-changed';
        this.state = 'active';
        if (wasInterrupted) {
            this.popup = null;
            this.env.ui.close();
            this.emit('restored', { session });
            this.flushWaiters(true);
        }
        this.emit('session', { session });
    }

    private unauthenticated(reason: UnauthenticatedReason): void {
        if (this.state === 'unauthenticated') return;
        this.state = 'unauthenticated';
        if (!this.emit('unauthenticated', { reason })) return;

        if (this.options.onUnauthenticated === 'redirect') {
            this.login();
            return;
        }
        this.env.ui.showUnauthenticated({
            reason,
            onPopup: () => this.openLoginPopup(),
            onRedirect: () => this.login(),
        });
    }

    private userChanged(user: SessionUser | null): void {
        this.state = 'user-changed';
        this.env.ui.close();
        this.flushWaiters(false);
        if (!this.emit('user-changed', { previousSub: this.expectedSub, user })) return;

        this.env.ui.showUserChanged({ name: user?.name ?? null, onReload: () => this.leave(() => this.env.reload()) });
    }

    private openLoginPopup(): void {
        const popup = this.env.openPopup(loginUrl(POPUP_DONE_PATH));
        if (popup) {
            this.popup = popup;
        } else {
            // Blokiran popup: prijava na posebnoj strani.
            this.login();
        }
    }

    private leave(go: () => void): void {
        this.state = 'leaving';
        this.flushWaiters(false);
        go();
    }

    private tick(): void {
        const marker = this.env.readCookie(MARKER_COOKIE);
        if (marker !== this.marker) {
            this.marker = marker;
            if (marker === null) this.markerReason = 'logged_out';
            void this.check(true);
        }
        if (this.popup?.closed) {
            this.popup = null;
            void this.check(true);
        }
    }

    private onMessage(event: MessageEvent): void {
        const data = event.data as { type?: unknown } | null;
        if (event.origin === this.env.origin && data?.type === 'kancelarko:login') void this.check(true);
    }

    /** `false` kad je aplikacija preuzela događaj (preventDefault). */
    private emit<K extends keyof GatewayEventMap>(type: K, detail: GatewayEventMap[K]): boolean {
        let prevented = false;
        const event: GatewayEvent<K> = { type, detail, preventDefault: () => (prevented = true) };
        for (const listener of this.listeners.get(type) ?? []) {
            try {
                (listener as GatewayListener<K>)(event);
            } catch (error) {
                console.error('kancelarko gateway: greška u obradi događaja', type, error);
            }
        }

        return !prevented;
    }
}
