/**
 * Sve što klijent traži od browser-a, iza interfejsa, da logika može da se testira bez DOM-a.
 */
export interface Env {
    /** Originalni fetch (pre presretanja). */
    fetch: typeof fetch;
    origin: string;
    href(): string;
    assign(url: string): void;
    reload(): void;
    readCookie(name: string): string | null;
    now(): number;
    every(ms: number, fn: () => void): void;
    listen(target: 'window' | 'document', type: string, fn: (event: Event) => void, capture?: boolean): void;
    visible(): boolean;
    openPopup(url: string): Popup | null;
    /** Odjava je samo POST (gateway), zato forma, a ne link. */
    postLogout(): void;
    ui: Ui;
}

export interface Popup {
    readonly closed: boolean;
}

export interface Ui {
    showUnauthenticated(options: { reason: string; onPopup: () => void; onRedirect: () => void }): void;
    showUserChanged(options: { name: string | null; onReload: () => void }): void;
    close(): void;
}

export function browserEnv(win: Window, ui: Ui): Env {
    const fetchOriginal = win.fetch.bind(win);

    return {
        fetch: fetchOriginal,
        origin: win.location.origin,
        href: () => win.location.href,
        assign: (url) => win.location.assign(url),
        reload: () => win.location.reload(),
        readCookie: (name) => readCookie(win.document.cookie, name),
        now: () => Date.now(),
        every: (ms, fn) => {
            win.setInterval(fn, ms);
        },
        listen: (target, type, fn, capture = false) => {
            (target === 'window' ? win : win.document).addEventListener(type, fn, { capture, passive: type !== 'submit' });
        },
        visible: () => win.document.visibilityState === 'visible',
        openPopup: (url) => win.open(url, 'kancelarko-login', 'popup,width=520,height=720'),
        postLogout: () => {
            const form = win.document.createElement('form');
            form.method = 'post';
            form.action = '/logout';
            form.style.display = 'none';
            win.document.body.appendChild(form);
            form.submit();
        },
        ui,
    };
}

export function readCookie(cookies: string, name: string): string | null {
    for (const part of cookies.split(';')) {
        const index = part.indexOf('=');
        if (index > 0 && part.slice(0, index).trim() === name) {
            const value = part.slice(index + 1).trim();
            return value === '' ? null : value;
        }
    }

    return null;
}
