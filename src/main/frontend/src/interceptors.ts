import type { GatewayClient } from './client.ts';

type Hooks = Pick<GatewayClient, 'headersFor' | 'isBlocked' | 'afterResponse'>;

export class BlockedRequestError extends Error {
    constructor() {
        super('Prijavljen je drugi korisnik; zahtev nije poslat. Osvežite stranu.');
        this.name = 'BlockedRequestError';
    }
}

/**
 * fetch aplikacije ka istom origin-u: dodaje `X-Requested-With` i `X-Kancelarko-Sub`, posle 401 čeka
 * ponovnu prijavu i ponavlja zahtev jednom (osim kad je telo stream, koji ne može ponovo da se pošalje).
 * Zahtevi ka drugim origin-ima prolaze netaknuti.
 */
export function interceptFetch(win: { fetch: typeof fetch }, hooks: Hooks): void {
    const original = win.fetch;

    win.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!hooks.headersFor(url)) return original(input, init);

        const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
        if (hooks.isBlocked(method)) throw new BlockedRequestError();

        const replay = input instanceof Request ? input.clone() : input;
        const send = (request: RequestInfo | URL) => original(request, withHeaders(request, init, hooks.headersFor(url) ?? {}));

        const response = await send(input);
        const action = await hooks.afterResponse(response.status, () => reasonOf(response));
        if (action === 'retry' && !(init?.body instanceof ReadableStream)) {
            if (hooks.isBlocked(method)) throw new BlockedRequestError();
            return send(replay);
        }

        return response;
    };
}

/**
 * XHR (jQuery, axios): dodaje samo `X-Kancelarko-Sub`. `X-Requested-With` jQuery već postavlja, a dvostruko
 * zaglavlje bi se spojilo u jednu vrednost. Ne ponavlja zahtev; 401 i 409 samo pokreću proveru sesije.
 */
export function interceptXhr(win: { XMLHttpRequest: typeof XMLHttpRequest }, hooks: Hooks): void {
    const proto = win.XMLHttpRequest.prototype;
    const open = proto.open;
    const send = proto.send;
    const requests = new WeakMap<XMLHttpRequest, { method: string; url: string }>();

    proto.open = function (this: XMLHttpRequest, method: string, url: string | URL, ...rest: unknown[]) {
        requests.set(this, { method, url: String(url) });
        return (open as (...args: unknown[]) => void).call(this, method, url, ...rest);
    } as typeof proto.open;

    proto.send = function (this: XMLHttpRequest, body?: Document | XMLHttpRequestBodyInit | null) {
        const request = requests.get(this);
        const headers = request && hooks.headersFor(request.url);
        if (request && headers) {
            if (hooks.isBlocked(request.method)) throw new BlockedRequestError();
            const subject = Object.entries(headers).find(([name]) => name !== 'X-Requested-With');
            if (subject) this.setRequestHeader(subject[0], subject[1]);
            this.addEventListener('loadend', () => {
                void hooks.afterResponse(this.status, async () => reasonFromText(this.responseType === '' || this.responseType === 'text' ? this.responseText : ''));
            });
        }

        return send.call(this, body);
    };
}

function withHeaders(input: RequestInfo | URL, init: RequestInit | undefined, extra: Record<string, string>): RequestInit {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    for (const [name, value] of Object.entries(extra)) {
        if (name === 'X-Requested-With' && headers.has(name)) continue;
        headers.set(name, value);
    }

    return { ...init, headers };
}

async function reasonOf(response: Response): Promise<string | null> {
    try {
        return reasonFromText(await response.clone().text());
    } catch {
        return null;
    }
}

function reasonFromText(text: string): string | null {
    try {
        const body = JSON.parse(text) as { reason?: unknown; error?: unknown } | null;
        const value = body?.reason ?? body?.error;
        return typeof value === 'string' ? value : null;
    } catch {
        return null;
    }
}
