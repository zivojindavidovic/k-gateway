import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { GatewayClient, MARKER_COOKIE, SUBJECT_HEADER } from '../src/client.ts';
import type { Env, Popup } from '../src/env.ts';
import { readCookie } from '../src/env.ts';
import { BlockedRequestError, interceptFetch } from '../src/interceptors.ts';
import type { Options, Session } from '../src/types.ts';

const ORIGIN = 'https://fakture.kancelarko.local';
const ANA = 'license:3:user:7';
const MARKO = 'license:3:user:9';

function session(sub: string | null, name = 'Ana'): Session {
    if (sub === null) return { v: 1, authenticated: false, reason: 'no_session', user: null, session: null };
    return {
        v: 1,
        authenticated: true,
        reason: null,
        user: { sub, sid: 's-1', licenseId: 3, userId: 7, role: 'ADMIN', modules: ['fakture'], name, email: null },
        session: { authTime: 1, accessTokenExpiresAt: 2, idleTimeout: 28800 },
    };
}

/** Browser bez DOM-a: vreme, tajmeri, cookie, događaji i gateway su pod kontrolom testa. */
class FakeBrowser {
    time = 0;
    cookie: string | null = 'm-1';
    gateway: Session = session(ANA);
    sessionCalls = 0;
    visible = true;
    popup: { closed: boolean } | null = null;
    popupBlocked = false;
    assigned: string[] = [];
    reloaded = 0;
    loggedOut = 0;
    shown: string[] = [];
    unauthenticatedDialog: { onPopup: () => void; onRedirect: () => void } | null = null;
    timers: Array<{ ms: number; fn: () => void }> = [];
    handlers = new Map<string, Array<(event: Event) => void>>();

    env(): Env {
        return {
            fetch: (async (url: RequestInfo | URL) => {
                assert.equal(url, '/bff/session');
                this.sessionCalls++;
                return Response.json(this.gateway);
            }) as typeof fetch,
            origin: ORIGIN,
            href: () => `${ORIGIN}/invoices/5`,
            assign: (url) => this.assigned.push(url),
            reload: () => this.reloaded++,
            readCookie: (name) => (name === MARKER_COOKIE ? this.cookie : null),
            now: () => this.time,
            every: (ms, fn) => {
                this.timers.push({ ms, fn });
            },
            listen: (target, type, fn) => {
                const key = `${target}:${type}`;
                this.handlers.set(key, [...(this.handlers.get(key) ?? []), fn]);
            },
            visible: () => this.visible,
            openPopup: (): Popup | null => {
                if (this.popupBlocked) return null;
                this.popup = { closed: false };
                return this.popup;
            },
            postLogout: () => this.loggedOut++,
            ui: {
                showUnauthenticated: (options) => {
                    this.shown.push(`unauthenticated:${options.reason}`);
                    this.unauthenticatedDialog = options;
                },
                showUserChanged: (options) => {
                    this.shown.push(`user-changed:${options.name}`);
                },
                close: () => {
                    this.shown.push('close');
                    this.unauthenticatedDialog = null;
                },
            },
        };
    }

    /** Pomeri vreme i okine tajmere čiji je interval prošao. */
    async advance(ms: number): Promise<void> {
        for (let elapsed = 0; elapsed < ms; elapsed += 1000) {
            this.time += 1000;
            for (const timer of this.timers) if (this.time % timer.ms === 0) timer.fn();
            await settle();
        }
    }

    async fire(target: 'window' | 'document', type: string, event: Partial<Event> & Record<string, unknown> = {}): Promise<void> {
        for (const handler of this.handlers.get(`${target}:${type}`) ?? []) handler(event as Event);
        await settle();
    }
}

async function settle(): Promise<void> {
    for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

const OPTIONS: Options = { expectedSub: null, pollInterval: 60_000, onUnauthenticated: 'dialog', intercept: true };

async function started(browser: FakeBrowser, options: Partial<Options> = {}): Promise<GatewayClient> {
    const client = new GatewayClient(browser.env(), { ...OPTIONS, ...options });
    client.start();
    await client.ready;
    return client;
}

describe('GatewayClient', () => {
    let browser: FakeBrowser;

    beforeEach(() => {
        browser = new FakeBrowser();
    });

    it('prva provera utvrđuje korisnika strane', async () => {
        const client = await started(browser);

        assert.equal(client.getState(), 'active');
        assert.equal(client.getUser()?.sub, ANA);
        assert.ok(client.hasModule('fakture'));
        assert.ok(!client.hasModule('kadrovik'));
        assert.ok(client.hasRole('USER', 'ADMIN'));
        assert.equal(client.headersFor('/api/invoices')?.[SUBJECT_HEADER], ANA);
    });

    it('nestanak K_GATEWAY_STATE je odjava u drugom tabu: prozor za prijavu bez mrežnog čekanja', async () => {
        await started(browser);
        browser.cookie = null;
        browser.gateway = session(null);

        await browser.advance(1000);

        assert.deepEqual(browser.shown, ['unauthenticated:logged_out']);
    });

    it('drugi korisnik prijavljen u drugom tabu: strana se blokira i traži osvežavanje', async () => {
        const client = await started(browser);
        browser.cookie = 'm-2';
        browser.gateway = session(MARKO, 'Marko');

        await browser.advance(1000);

        assert.equal(client.getState(), 'user-changed');
        assert.deepEqual(browser.shown, ['close', 'user-changed:Marko']);
        assert.ok(client.isBlocked('POST'));
        assert.ok(!client.isBlocked('GET'));
    });

    it('data-sub ima prednost nad prvim odgovorom gateway-a (zamena korisnika pre učitavanja klijenta)', async () => {
        browser.gateway = session(MARKO, 'Marko');
        const client = await started(browser, { expectedSub: ANA });

        assert.equal(client.getState(), 'user-changed');
    });

    it('prijava u popup-u istog korisnika vraća stranu bez osvežavanja', async () => {
        const client = await started(browser);
        browser.cookie = null;
        browser.gateway = session(null);
        await browser.advance(1000);

        browser.unauthenticatedDialog!.onPopup();
        assert.ok(browser.popup);
        browser.cookie = 'm-2';
        browser.gateway = session(ANA);
        await browser.advance(1000);

        assert.equal(client.getState(), 'active');
        assert.deepEqual(browser.shown, ['unauthenticated:logged_out', 'close']);
    });

    it('blokiran popup vodi na prijavu na posebnoj strani', async () => {
        browser.popupBlocked = true;
        browser.gateway = session(null);
        const client = await started(browser);

        browser.unauthenticatedDialog!.onPopup();

        assert.equal(client.getState(), 'leaving');
        assert.deepEqual(browser.assigned, [`/bff/login?returnTo=${encodeURIComponent(`${ORIGIN}/invoices/5`)}`]);
    });

    it('redirect mod odmah šalje na prijavu', async () => {
        browser.gateway = session(null);
        await started(browser, { onUnauthenticated: 'redirect' });

        assert.equal(browser.assigned.length, 1);
        assert.deepEqual(browser.shown, []);
    });

    it('aplikacija može da preuzme događaj (preventDefault)', async () => {
        const client = new GatewayClient(browser.env(), OPTIONS);
        const reasons: string[] = [];
        client.on('unauthenticated', (event) => {
            reasons.push(event.detail.reason);
            event.preventDefault();
        });
        browser.gateway = session(null);
        client.start();
        await client.ready;

        assert.deepEqual(reasons, ['no_session']);
        assert.deepEqual(browser.shown, []);
    });

    it('periodična provera samo dok je tab vidljiv i korisnik radi (svaka provera produžava sesiju)', async () => {
        await started(browser);
        const afterStart = browser.sessionCalls;

        await browser.advance(120_000);
        assert.equal(browser.sessionCalls, afterStart, 'bez aktivnosti nema provere');

        await browser.advance(30_000);
        await browser.fire('window', 'keydown');
        await browser.advance(30_000);
        assert.equal(browser.sessionCalls, afterStart + 1);

        browser.visible = false;
        await browser.advance(30_000);
        await browser.fire('window', 'keydown');
        await browser.advance(30_000);
        assert.equal(browser.sessionCalls, afterStart + 1, 'skriven tab se ne proverava');
    });

    it('fokus proverava sesiju, ali ne češće od jednom u 3 s', async () => {
        await started(browser);
        const afterStart = browser.sessionCalls;
        browser.time += 5000;

        await browser.fire('window', 'focus');
        await browser.fire('window', 'focus');

        assert.equal(browser.sessionCalls, afterStart + 1);
    });

    it('forma se ne šalje dok sesije nema', async () => {
        browser.gateway = session(null);
        await started(browser);
        let prevented = false;

        await browser.fire('document', 'submit', { preventDefault: () => (prevented = true), stopImmediatePropagation: () => {} });

        assert.ok(prevented);
    });

    it('odjava je POST forma, bez reakcije na sopstveno brisanje cookie-ja', async () => {
        const client = await started(browser);

        client.logout();
        browser.cookie = null;
        await browser.advance(1000);

        assert.equal(browser.loggedOut, 1);
        assert.deepEqual(browser.shown, []);
    });

    it('zaglavlja samo za isti origin i ne za putanje gateway-a', async () => {
        const client = await started(browser);

        assert.ok(client.headersFor('/api/x'));
        assert.ok(client.headersFor(`${ORIGIN}/api/x`));
        assert.equal(client.headersFor('https://adresar.kancelarko.local/api/x'), null);
        assert.equal(client.headersFor('/bff/session'), null);
    });
});

describe('interceptFetch', () => {
    it('401 → prijava u popup-u → isti zahtev ponovo, sa zaglavljima', async () => {
        const browser = new FakeBrowser();
        const client = await started(browser);
        const calls: Array<{ url: string; headers: Headers }> = [];
        let status = 401;
        const win = {
            fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
                calls.push({ url: String(input), headers: new Headers(init?.headers) });
                return new Response('{"error":"unauthorized","reason":"no_session"}', { status });
            }) as typeof fetch,
        };
        interceptFetch(win, client);
        browser.gateway = session(null);

        const pending = win.fetch('/api/invoices', { method: 'POST', body: '{"a":1}' });
        await settle();
        assert.deepEqual(browser.shown, ['unauthenticated:no_session']);

        status = 200;
        browser.unauthenticatedDialog!.onPopup();
        browser.gateway = session(ANA);
        browser.popup!.closed = true;
        await browser.advance(1000);

        const response = await pending;
        assert.equal(response.status, 200);
        assert.equal(calls.length, 2);
        assert.equal(calls[1].headers.get(SUBJECT_HEADER), ANA);
        assert.equal(calls[1].headers.get('X-Requested-With'), 'XMLHttpRequest');
    });

    it('posle zamene korisnika POST se ne šalje', async () => {
        const browser = new FakeBrowser();
        const client = await started(browser);
        let sent = 0;
        const win = {
            fetch: (async () => {
                sent++;
                return new Response('{}');
            }) as typeof fetch,
        };
        interceptFetch(win, client);
        browser.cookie = 'm-2';
        browser.gateway = session(MARKO);
        await browser.advance(1000);

        await assert.rejects(win.fetch('/api/invoices', { method: 'POST' }), BlockedRequestError);
        await win.fetch('/api/invoices');
        assert.equal(sent, 1);
    });

    it('409 user_changed sa gateway-a pokreće proveru sesije', async () => {
        const browser = new FakeBrowser();
        const client = await started(browser);
        const win = {
            fetch: (async () => new Response('{"error":"user_changed"}', { status: 409 })) as typeof fetch,
        };
        interceptFetch(win, client);
        browser.gateway = session(MARKO, 'Marko');

        await win.fetch('/api/invoices', { method: 'POST' });
        await settle();

        assert.equal(client.getState(), 'user-changed');
    });

    it('tuđ origin ide bez zaglavlja i bez presretanja', async () => {
        const browser = new FakeBrowser();
        const client = await started(browser);
        let headers: Headers | null = null;
        const win = {
            fetch: (async (_: RequestInfo | URL, init?: RequestInit) => {
                headers = new Headers(init?.headers);
                return new Response('', { status: 401 });
            }) as typeof fetch,
        };
        interceptFetch(win, client);

        await win.fetch('https://api.example.com/x');

        assert.equal(headers!.get(SUBJECT_HEADER), null);
        assert.deepEqual(browser.shown, []);
    });
});

describe('readCookie', () => {
    it('čita vrednost po imenu', () => {
        assert.equal(readCookie('a=1; K_GATEWAY_STATE=abc; b=2', 'K_GATEWAY_STATE'), 'abc');
        assert.equal(readCookie('XK_GATEWAY_STATE=abc', 'K_GATEWAY_STATE'), null);
        assert.equal(readCookie('K_GATEWAY_STATE=', 'K_GATEWAY_STATE'), null);
    });
});
