/**
 * Kancelarko gateway klijent za browser: `<script src="/bff/sdk.js" defer></script>` na strani aplikacije
 * iza k-gateway-a. API je na `window.Kancelarko.gateway`.
 *
 * Podešavanja preko atributa script taga:
 *   data-sub="license:3:user:7"   korisnik za koga je strana napravljena (preporučeno; bez njega prvi odgovor gateway-a)
 *   data-poll="60"                periodična provera sesije u sekundama, dok korisnik radi
 *   data-on-unauthenticated="dialog|redirect"
 *   data-intercept="false"        bez presretanja fetch-a i XHR-a
 */
import { GatewayClient } from './client.ts';
import { browserEnv } from './env.ts';
import { interceptFetch, interceptXhr } from './interceptors.ts';
import type { Options } from './types.ts';
import { dialogUi } from './ui.ts';

export type { GatewayEvent, GatewayEventMap, Session, SessionInfo, SessionUser } from './types.ts';

export interface KancelarkoGateway {
    readonly ready: Promise<import('./types.ts').Session | null>;
    getSession: GatewayClient['getSession'];
    getUser: GatewayClient['getUser'];
    getState: GatewayClient['getState'];
    hasModule: GatewayClient['hasModule'];
    hasRole: GatewayClient['hasRole'];
    check: GatewayClient['check'];
    login: GatewayClient['login'];
    logout: GatewayClient['logout'];
    account: GatewayClient['account'];
    on: GatewayClient['on'];
}

declare global {
    interface Window {
        Kancelarko?: { gateway?: KancelarkoGateway };
    }
}

function readOptions(script: HTMLOrSVGScriptElement | null): Options {
    const data = script instanceof HTMLScriptElement ? script.dataset : {};
    const poll = Number.parseFloat(data.poll ?? '');

    return {
        expectedSub: data.sub?.trim() || null,
        pollInterval: (Number.isFinite(poll) && poll >= 15 ? poll : 60) * 1000,
        onUnauthenticated: data.onUnauthenticated === 'redirect' ? 'redirect' : 'dialog',
        intercept: data.intercept !== 'false',
    };
}

function install(): void {
    // Skripta uključena dva puta (layout + stranica) ne sme da pravi dva klijenta.
    if (window.Kancelarko?.gateway) return;

    const options = readOptions(document.currentScript);
    const client = new GatewayClient(browserEnv(window, dialogUi(document)), options);
    if (options.intercept) {
        interceptFetch(window, client);
        interceptXhr(window, client);
    }

    const api: KancelarkoGateway = {
        ready: client.ready,
        getSession: () => client.getSession(),
        getUser: () => client.getUser(),
        getState: () => client.getState(),
        hasModule: (module) => client.hasModule(module),
        hasRole: (...roles) => client.hasRole(...roles),
        check: (force) => client.check(force),
        login: (options) => client.login(options),
        logout: () => client.logout(),
        account: () => client.account(),
        on: (type, listener) => client.on(type, listener),
    };
    window.Kancelarko = { ...window.Kancelarko, gateway: Object.freeze(api) };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => client.start(), { once: true });
    } else {
        client.start();
    }
}

install();
