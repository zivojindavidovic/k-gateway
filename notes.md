# Izmene na k-gateway-u (oktobar 2026)

Gateway je do sada radio osnovno: prijava preko k-auth-a, prosleđivanje tokena aplikacijama, odjava.
Pregledom celog toka (gateway, k-fakture, k-auth) našlo se dosta rupa, uglavnom u onome što se dešava
u browseru kad korisnik ima više tabova ili više aplikacija otvoreno. Ovde je kratko šta je promenjeno i zašto.

## Glavna stvar: jedna skripta za sve aplikacije

Svaka aplikacija je do sada morala sama da proverava da li je korisnik još prijavljen (k-fakture je imao
svoj `session-guard.js`). Sada gateway sam servira skriptu na `/bff/sdk.js`, istu za sve aplikacije.
Aplikacija samo uključi `<script src="/bff/sdk.js" defer></script>`.

Izvor skripte (TypeScript) i njen build žive u k-gateway-client (`sdk/` → `dist/sdk.js`). Gateway je ne
gradi: gotova, minifikovana skripta je u `src/main/resources/bff/sdk.js` i ide u jar, pa nema CDN-a ni
Node-a u build-u gateway-a. Nova verzija: `npm run build` u k-gateway-client, pa
`cp ../k-gateway-client/dist/sdk.js src/main/resources/bff/sdk.js`. Kad se gateway ažurira, sve aplikacije
odmah dobiju novu verziju.

Šta skripta radi:

- **Odjava u drugom tabu ili aplikaciji se vidi skoro odmah.** Na ostalim stranama izlazi prozor
  "Odjavljeni ste", ne tek kad korisnik nešto klikne.
- **Prijava bez gubljenja posla.** Kad sesija istekne, korisnik se prijavi u malom prozoru (popup), a strana
  na kojoj je radio ostaje kakva je bila. Zahtev koji je pao zbog isteka šalje se ponovo sam.
- **Zamena korisnika.** Ako se u drugom tabu prijavi neko drugi (ili ista osoba na drugu licencu), stara
  strana se blokira i traži osvežavanje. Ranije je stara strana mogla da pošalje podatke pod novim
  korisnikom, na primer forma licence 1 upisana u licencu 2. To je bila najozbiljnija rupa.
- Periodično proverava sesiju, ali samo dok korisnik nešto radi na strani, da ne bi veštački držala sesiju živom.

## Šta je još promenjeno na gateway-u

**Sesija i stanje**
- `/bff/session` sada daje pravo stanje: osveži token ako treba, odmah vidi sesiju koju je k-auth opozvao
  (ne čeka back-channel) i kaže razlog kad sesije nema.
- Novi cookie `K_GATEWAY_STATE` (bez ikakvog pristupa, samo nasumična vrednost po prijavi). Po njemu skripta
  bez ijednog poziva serveru vidi odjavu ili novu prijavu u bilo kom tabu.
- Kad zahtev padne, odgovor kaže zašto (`no_session`, `session_revoked`, `refresh_failed`...), umesto praznog 401.

**Zaštita**
- **Zahtev sa tuđe strane se odbija.** Sve aplikacije su pod istim domenom, pa je jedna aplikacija mogla da
  pošalje POST drugoj sa korisnikovom sesijom (npr. preko XSS-a). Sada POST/PUT/PATCH/DELETE mora doći sa
  iste aplikacije na koju ide.
- **Odjava je samo POST.** `GET /logout` sada samo prikazuje potvrdu, da odjavu ne pokrene tuđ link ili slika.
- **Preusmeravanje samo na prave aplikacije.** Ranije je gateway preusmeravao na bilo koji poddomen
  (`*.kancelarko...`), pa i na one koji nisu naši ili su napušteni. Sada samo na hostove iz ruta, i samo `https`.
- Ograničen broj zahteva na prijavu, `/bff/session` i odjavu.
- Cookie sesije je podrazumevano `Secure`. Lokalno bez TLS-a treba `K_GATEWAY_COOKIE_SECURE=false`.
- Provera opozvanih sesija može da ima svog Redis korisnika (samo čitanje).
- Ako je podešeno da se ne propušta kad Redis ne radi (`fail-open=false`), korisnik dobija 503, a ne odjavu.

**Prijava iz više tabova**
- Započete prijave se čuvaju u Redis-u, a ne u sesiji. Kad su dva taba (ili tab i popup) istovremeno išla na
  prijavu, jedan je ponekad završavao greškom. Sada se svako vraća na svoju stranu. Prijava je vezana za
  browser cookie-jem `K_GATEWAY_BROWSER`, da tuđ link za povratak sa k-auth-a ne može da prijavi korisnika
  pod tuđim nalogom.

## Šta nije urađeno (nije do gateway-a)

- Sve aplikacije i dalje dobijaju isti token (`aud: k-gateway`). Da bi svaka imala svoj, k-auth treba da
  podrži zamenu tokena (token exchange). To je posao za k-auth.
- Aplikacije treba da prihvataju zahteve samo od gateway-a (`trustProxies` i mreža). To je posao za aplikacije i infrastrukturu.
- Redis korisnik samo za čitanje opoziva treba da se napravi u k-docker-u.
- Zajednički deo za aplikacije (komponenta `<x-gateway::client />`, vezivanje sesije za korisnika, grupa
  `gateway`) je prešao u `kancelarko/gateway-client`. k-fakture treba da povuče novu verziju paketa i
  izbaci svoje kopije (spisak u `k-fakture/notes.md`).

## Kako ručno testirati prozore za prijavu

k-fakture već uključuje skriptu, pa se sve testira direktno na `https://fakture.kancelarko.local`.
Na aplikaciji koja je još ne uključuje može ručno, u konzoli browsera (F12):

```js
const s = document.createElement('script'); s.src = '/bff/sdk.js'; document.head.append(s);
```

Test korisnici: `developer-1`, `developer-2`,
`developer-3` `@paragraf.rs`, lozinka `password`.

**1. Odjava u drugom tabu → prijava u popup-u**
1. Otvori fakture u dva taba (A i B) i u A ukucaj nešto u neko polje, bez čuvanja.
2. U B klikni "Odjava naloga" (ili u konzoli `Kancelarko.gateway.logout()`).
3. U A za sekundu izlazi prozor "Odjavljeni ste".
4. Klikni "Prijavi se", pa se prijavi u malom prozoru. Prozor se sam zatvara, A nastavlja rad i uneti tekst je i dalje tu.
5. Isto, ali klikni "Prijava na posebnoj strani": ide na prijavu i posle nje vraća na istu stranu (uneto se tada gubi).

**2. Sesija istekla, bez drugog taba**
1. U RedisInsight-u (`https://redisinsight.kancelarko.local`), baza 3, obriši ključeve `k-gateway:session:*`.
2. Vrati se u tab sa fakturama (klik na tab ili bilo šta na strani). Izlazi "Sesija je istekla".
3. Ako je strana u tom trenutku slala zahtev (npr. čuvanje), posle prijave u popup-u šalje se ponovo sama.

**3. Sesija opozvana u k-auth-u**
1. U konzoli `Kancelarko.gateway.getUser().sid` pa kopiraj vrednost.
2. U RedisInsight-u, baza 2, dodaj ključ `k-auth:revoked-sid:<sid>` sa bilo kojom vrednošću.
3. Klikni u tab. Izlazi "Sesija je prekinuta".

**4. Drugi korisnik u drugom tabu**
1. Tab A: prijavljen kao `developer-3`.
2. Tab B: odjavi se, pa se prijavi kao `developer-2`.
3. U A izlazi "Prijavljen je drugi korisnik" i forme na strani se ne šalju. Jedino dugme je "Osveži stranu".

**5. Blokiran popup**
U podešavanjima browsera blokiraj popup prozore za `fakture.kancelarko.local` i ponovi test 1. Klik na
"Prijavi se" tada vodi na prijavu na posebnoj strani.

**Korisno u konzoli**
- `Kancelarko.gateway.getState()`: `active`, `unauthenticated`, `user-changed`
- `Kancelarko.gateway.getUser()`: ko je prijavljen (sub, licenca, rola, moduli)
- `Kancelarko.gateway.check(true)`: odmah pita gateway za stanje

Ako popup ne radi, u logu gateway-a (`docker compose logs -f k-gateway`) potraži "Prijava preko k-auth-a nije uspela".
