import type { Ui } from './env.ts';

const TITLES: Record<string, string> = {
    logged_out: 'Odjavljeni ste',
    session_revoked: 'Sesija je prekinuta',
};

const STYLE = `
:host{all:initial}
dialog{border:0;border-radius:12px;padding:24px;max-width:420px;width:calc(100% - 32px);box-sizing:border-box;
  font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1f2933;background:#fff;
  box-shadow:0 20px 50px rgba(0,0,0,.25)}
dialog::backdrop{background:rgba(15,23,42,.55)}
h2{margin:0 0 8px;font-size:18px;font-weight:600}
p{margin:0 0 20px}
.actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
button{font:inherit;border-radius:8px;padding:8px 16px;cursor:pointer;border:1px solid #cbd2d9;background:#fff;color:inherit}
button.primary{background:#1d4ed8;border-color:#1d4ed8;color:#fff}
button:focus-visible{outline:2px solid #1d4ed8;outline-offset:2px}
@media (prefers-color-scheme:dark){dialog{background:#1f2933;color:#e4e7eb}button{background:#323f4b;border-color:#52606d}}
`;

/**
 * Prozori klijenta, isti u svim aplikacijama. U shadow DOM-u, da ih stilovi aplikacije ne menjaju.
 * Ne zatvaraju se na Esc: strana ne sme dalje dok se stanje sesije ne razreši.
 */
export function dialogUi(doc: Document): Ui {
    let host: HTMLElement | null = null;
    let dialog: HTMLDialogElement | null = null;

    function open(title: string, text: string, buttons: Array<{ label: string; primary?: boolean; onClick: () => void }>) {
        close();
        host = doc.createElement('kancelarko-session-dialog');
        const root = host.attachShadow({ mode: 'open' });
        const style = doc.createElement('style');
        style.textContent = STYLE;
        dialog = doc.createElement('dialog');
        dialog.setAttribute('aria-labelledby', 'k-title');
        const heading = doc.createElement('h2');
        heading.id = 'k-title';
        heading.textContent = title;
        const paragraph = doc.createElement('p');
        paragraph.textContent = text;
        const actions = doc.createElement('div');
        actions.className = 'actions';
        for (const button of buttons) {
            const element = doc.createElement('button');
            element.type = 'button';
            element.textContent = button.label;
            if (button.primary) element.className = 'primary';
            element.addEventListener('click', button.onClick);
            actions.appendChild(element);
        }
        dialog.append(heading, paragraph, actions);
        dialog.addEventListener('cancel', (event) => event.preventDefault());
        root.append(style, dialog);
        doc.body.appendChild(host);
        dialog.showModal();
    }

    function close() {
        dialog?.close();
        host?.remove();
        host = null;
        dialog = null;
    }

    return {
        showUnauthenticated({ reason, onPopup, onRedirect }) {
            open(
                TITLES[reason] ?? 'Sesija je istekla',
                'Prijavite se ponovo da biste nastavili. Prijava se otvara u novom prozoru, pa ono što ste uneli na ovoj strani ostaje.',
                [
                    { label: 'Prijava na posebnoj strani', onClick: onRedirect },
                    { label: 'Prijavi se', primary: true, onClick: onPopup },
                ],
            );
        },
        showUserChanged({ name, onReload }) {
            const who = name ? ` (${name})` : '';
            open(
                'Prijavljen je drugi korisnik',
                `U drugom prozoru je prijavljen drugi korisnik ili druga licenca${who}. Ova strana pripada prethodnoj prijavi, pa se izmene sa nje ne šalju. Osvežite stranu.`,
                [{ label: 'Osveži stranu', primary: true, onClick: onReload }],
            );
        },
        close,
    };
}
