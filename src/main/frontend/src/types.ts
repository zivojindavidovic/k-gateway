/** Odgovor `GET /bff/session` (BffController.SessionResponse). */
export interface Session {
    /** Verzija odgovora; nova polja dolaze uz novu verziju. */
    v: number;
    authenticated: boolean;
    /** Zašto sesije nema: `no_session`, `session_revoked`, `refresh_failed`. */
    reason: string | null;
    user: SessionUser | null;
    session: SessionInfo | null;
}

export interface SessionUser {
    /** `license:{licenca}:user:{korisnik}`: isti sub = isti korisnik na istoj licenci. */
    sub: string | null;
    sid: string | null;
    licenseId: unknown;
    userId: unknown;
    role: string | null;
    modules: unknown;
    name: string | null;
    email: string | null;
}

export interface SessionInfo {
    /** Unix sekunde. */
    authTime: number | null;
    accessTokenExpiresAt: number | null;
    /** Sekunde bez aktivnosti posle kojih sesija gateway-a ističe. */
    idleTimeout: number;
}

/**
 * Zašto korisnik više nije prijavljen: razlozi gateway-a, plus `logged_out` kad je odjava viđena
 * po nestanku cookie-ja `K_GATEWAY_STATE` (odjava u drugom tabu ili aplikaciji).
 */
export type UnauthenticatedReason = 'no_session' | 'session_revoked' | 'refresh_failed' | 'invalid_token' | 'logged_out' | string;

export interface Options {
    /** Korisnik za koga je strana napravljena (`data-sub`); bez njega prvi odgovor `/bff/session`. */
    expectedSub: string | null;
    /** Periodična provera sesije, ms; samo dok je tab vidljiv i korisnik nešto radi. */
    pollInterval: number;
    /** `dialog`: prozor sa prijavom u popup-u, rad na strani ostaje; `redirect`: odmah na prijavu. */
    onUnauthenticated: 'dialog' | 'redirect';
    /** Presretanje fetch-a i XHR-a ka istom origin-u (zaglavlja, 401, 409). */
    intercept: boolean;
}

export interface GatewayEventMap {
    /** Sesija proverena i važi. */
    session: { session: Session };
    /** Korisnik više nije prijavljen. Podrazumevano: prozor za prijavu ili preusmeravanje. */
    unauthenticated: { reason: UnauthenticatedReason };
    /** Prijava ponovo važi (isti korisnik), npr. posle prijave u popup-u. */
    restored: { session: Session };
    /** U drugom tabu/aplikaciji prijavljen drugi korisnik ili druga licenca. Podrazumevano: prozor sa osvežavanjem. */
    'user-changed': { previousSub: string | null; user: SessionUser | null };
}

export interface GatewayEvent<K extends keyof GatewayEventMap> {
    type: K;
    detail: GatewayEventMap[K];
    /** Aplikacija sama obrađuje događaj; klijent ne prikazuje svoj prozor i ne preusmerava. */
    preventDefault(): void;
}

export type GatewayListener<K extends keyof GatewayEventMap> = (event: GatewayEvent<K>) => void;
