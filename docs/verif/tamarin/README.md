# 07 — Verifica formale del protocollo (Tamarin Prover)

Questo documento descrive la verifica formale del protocollo RA5G tramite
[Tamarin Prover](https://tamarin-prover.com/), un complemento alla
verifica empirica già coperta da `go test`: mentre i test Go verificano
scenari *specifici* che abbiamo pensato di testare, Tamarin prova
**matematicamente** che certe proprietà valgano per **ogni** sequenza
possibile di azioni, contro un attaccante che intercetta, altera, rigioca
e inventa messaggi (modello standard **Dolev-Yao**).

I file del modello sono in questa stessa cartella (`verif/tamarin/`).

## Risultato finale

**Tutti e 14 i lemmi individuati sono `verified`, con zero warning**,
distribuiti su 7 file — ciascuno con solo le regole necessarie alle
proprietà che dimostra (vedi [perché la teoria non è un unico
file](#perché-più-file-invece-di-un-unico-file-monolitico) più sotto):

| File | Lemmi | Tempo |
|---|---|---|
| `ra5g_boot_renew.spthy` | `executability`, `fail_closed_requires_valid_attestation`, `no_replay` | < 1s |
| `ra5g_revocation.spthy` | `revocation_effective` | 0.94s |
| `ra5g_migration_single.spthy` | `migration_executability`, `migration_requires_source_validation`, `old_generation_not_routable_after_migration`, `migration_atomicity` | 2.21s |
| `ra5g_generation_exclusivity_chain.spthy` | `chain_executability`, `migration_chain_strict_ordering`, `old_generation_not_routable_after_second_migration`, `migration_atomicity2` | 21.54s |
| `ra5g_orchestrator_authority.spthy` | `orchestrator_non_authority_attestation` | 0.44s |
| `ra5g_orchestrator_authority_migration.spthy` | `orchestrator_non_authority_migration` | 0.85s |
| `ra5g_boot_renew_MUTATO_dimostrazione.spthy` | (stessi 3 di boot_renew, ma volutamente rotti) | — test di mutazione, vedi sotto |

Copre Bootstrap, Continuous Attestation, il canale di revoca immediata, e
una **catena di due Migrazioni Cooperative** (g0→g1→g2) — l'intero
protocollo così come implementato in
`agent.go`/`verifier.go`/`enforcement.go`.

## Mappatura ai sei obiettivi di sicurezza del documento di analisi

Il documento di analisi originale ("paper di partenza") elenca sei
obiettivi di sicurezza (§III-C). Questa tabella mappa ciascuno ai lemmi
che lo dimostrano, con lo stato reale — non tutti sono coperti nello
stesso modo, ed è importante saperlo prima di citare questi risultati:

| Obiettivo (dal paper) | Lemma/i Tamarin | Stato |
|---|---|---|
| **No premature trust** — *"no generation becomes routable before its evidence is verified by V"* | `fail_closed_requires_valid_attestation` | ✅ Dimostrata |
| **Orchestrator non-authority** — *"no sequence of Orch-originated messages... causes token issuance/renewal absent valid hardware-rooted evidence"* | `orchestrator_non_authority_attestation`, `orchestrator_non_authority_migration` | ✅ Dimostrata |
| **Generation exclusivity** — *"E never simultaneously routes to two live generations of the same logical instance"* | `old_generation_not_routable_after_migration`, `old_generation_not_routable_after_second_migration`, `migration_chain_strict_ordering` | ✅ Dimostrata temporalmente; l'esclusione simultanea è inoltre garantita strutturalmente dalla natura lineare dei fatti `Live`/`RouteOK` (non possono coesistere due istanze per lo stesso `id`) |
| **Migration atomicity** — *"a source generation's revocation and a destination generation's admission are bound such that no window exists where both, or neither, hold"* | `migration_atomicity`, `migration_atomicity2` | ✅ Dimostrata — con una precisazione: `GenerationRetracted`/`GenerationAdmitted` sono azioni aggiunte sulla stessa regola `Verifier_CompleteMigration`/`2`, e "nessuna finestra" è tradotta come "stesso istante" (`#i = #j`), la forma più fedele possibile nella semantica discreta di Tamarin (nessun concetto di durata). La dimostrazione discende in parte dalla struttura stessa della regola (atomicità intrinseca del multiset rewriting), non è una scoperta indipendente come altri lemmi — ma è comunque la formalizzazione esplicita, citabile, della proprietà nel linguaggio del paper |
| **Freshness** — *"evidence accepted by V is never older than a bounded staleness window"* | `no_replay` | ⚠️ **Coperta solo parzialmente**: `no_replay` dimostra che un nonce non può essere riusato (condizione necessaria), ma la definizione del paper richiede un limite di tempo *quantitativo* (un TTL) — cosa che Tamarin non può esprimere nella sua forma simbolica: ragiona solo per ordinamento relativo tra eventi (`#i < #j`), mai per durate reali |
| **TOCTOU-continuity** — *"a compromise occurring strictly between two attestation events cannot be permanently concealed by a subsequent, seemingly-legitimate quote"* | — | ❌ **Non formalizzata** — non un gap della nostra modellazione, ma un confine esplicitamente dichiarato dal paper stesso. Vedi la sezione dedicata più sotto. |

## Perché più file invece di un unico file monolitico

Un tentativo di unificare tutte le regole e tutti i lemmi in un'unica
teoria consolidata non converge in tempi ragionevoli, anche dopo aver
corretto i problemi di fedeltà descritti nella cronologia più sotto. La
causa non è la falsità di una qualunque proprietà, ma la crescita rapida
dello spazio di casi che il risolutore automatico deve escludere quando
l'insieme delle regole aumenta: ogni regola viene considerata
potenzialmente rilevante per ogni lemma, anche quando in pratica non lo
è.

La soluzione adottata — pratica riconosciuta in Tamarin quando una
teoria completa risulta intrattabile — consiste nel mantenere più teorie
mirate, ciascuna con solo le regole necessarie ai lemmi che dimostra.
Questo non indebolisce la validità dei risultati: ogni file costituisce
una teoria autonoma e coerente, e ciascun lemma viene dimostrato
esplorando l'intero spazio delle tracce possibili all'interno di quella
teoria, come richiesto da una prova `all-traces`. La rimozione di regole
non necessarie a un lemma non altera la validità della dimostrazione per
quel lemma; ne riduce soltanto lo sforzo computazionale.

### Mappatura regole Tamarin → codice Go

| Regola Tamarin | Corrisponde a |
|---|---|
| `Setup_Verifier` | `verifier.New()` — genera sk_V/pk_V |
| `Setup_Agent` | `RegisterInstance` (onboarding istanza, fidato per definizione — l'assunzione EK→AK) |
| `Setup_TargetAgent` (e varianti `1`/`2`) | Onboarding dell'host target in `CompleteMigration` (stessa assunzione, per ciascun nuovo TPM) |
| `Verifier_ChallengeBoot` / `Verifier_ChallengeRenew` | `v.GenerateNonce(instanceID)` |
| `Agent_ProduceBootQuote` / `Agent_ProduceRenewQuote` | `a.GetTPMQuote(...)` + `model.ContextBoundNonce(...)` |
| `Verifier_AcceptBoot` / `Verifier_AcceptRenew` | `v.VerifyQuote(...)` seguito da `v.IssueToken(...)` (unite in una regola: tra i due non c'è interazione di rete intercettabile) |
| `Verifier_DetectReplayAndRevoke` | `verifyQuoteLocked` (ramo replay) + `v.fireRevokeHooks` + `Enforcement.Revoke` — modellata come un'unica transizione di sistema, non come messaggi di rete, perché nel codice reale è una chiamata di funzione interna a un solo processo fidato |
| `Verifier_BeginMigration` (e `2`) | `v.BeginMigration(...)` |
| `Agent_ProduceMigrationSourceQuote` (e `2`) | `agent.GetMigrationSourceQuote(...)` + `model.MigrationSourceBoundNonce(...)` |
| `Verifier_ValidateMigrationSource` (e `2`) | `v.ValidateMigrationSource(...)` |
| `Agent_ProduceMigrationTargetQuote` (e `2`) | `agent.GetTPMQuote(...)` sull'host target, tag Migrate |
| `Verifier_CompleteMigration` (e `2`) | `v.CompleteMigration(...)` — l'Atomic Commit |
| `Enforcement_AdmitRouting` | `e.UpdateRoutingRules(token)` |

### Semplificazioni deliberate (dichiarate, non nascoste)

- **Crittografia simbolica**: `sign`/`verify`/`pk` sono termini simbolici
  con un'equazione (`verify(sign(m,sk), m, pk(sk)) = true`), non vera
  matematica RSA/SHA-256.
- **Generazioni simboliche fisse (`'g0'`/`'g1'`/`'g2'`)**, non numeriche
  arbitrarie: sufficiente per provare le proprietà qualitative che
  contano, senza la complessità di una codifica aritmetica esplicita.
- **Golden Measurement come costante pubblica `'golden'`**: il confronto
  PCR reale non è modellato — la sua sicurezza dipende dall'integrità
  della firma TPM, già coperta dal modello di firma simbolico.
- **Bootstrap limitato a un solo utilizzo per istanza** (`NotYetLive`) e
  **Renew limitato a un solo rinnovo** (`RenewAllowed`), dove presenti:
  necessario per la trattabilità della ricerca automatica — vedi la
  cronologia sotto.
- **Ciascuna Migrazione limitata a un solo tentativo per istanza**
  (`MigrationAllowed`/`Migration2Allowed`, dove presenti), stesso motivo.

## I quattordici lemmi — cosa provano, in termini semplici

1. **`executability`** / **`migration_executability`** /
   **`chain_executability`** — controlli di sanità: il protocollo può
   completare un bootstrap, una migrazione, e una catena di due
   migrazioni con successo. Non sono proprietà di sicurezza; escludono
   che gli altri lemmi risultino "veri" solo perché il modello è
   vuoto/inutilizzabile.
2. **`fail_closed_requires_valid_attestation`** — nessuna sequenza
   dell'attaccante porta l'Enforcement ad ammettere il routing senza che
   il Verifier abbia prima accettato una quote genuina **o** completato
   una migrazione legittima per quella stessa generazione. Prova formale
   del principio Fail-Closed.
3. **`no_replay`** — nessuna sequenza produce due eventi di accettazione
   distinti con lo stesso nonce. Prova formale della protezione
   anti-replay.
4. **`revocation_effective`** — dopo che un replay viene rilevato,
   nessuna nuova accettazione legittima può più avvenire per quella
   generazione. Prova formale del canale di revoca immediata.
5. **`migration_requires_source_validation`** — nessuna migrazione può
   completarsi senza che Q_src sia stata validata prima. Prova formale
   di "Atomic Migration (Dual-Sided Authorization)".
6. **`old_generation_not_routable_after_migration`** — dopo una
   migrazione riuscita, la generazione precedente non può mai più essere
   (ri)accettata.
7. **`old_generation_not_routable_after_second_migration`** — la stessa
   proprietà, dimostrata **anche dopo una seconda migrazione**: g0 resta
   permanentemente bloccata lungo tutta la catena, non solo al primo
   confine.
8. **`migration_chain_strict_ordering`** — la prima migrazione (g0→g1)
   avviene sempre strettamente prima della seconda (g1→g2). Prova
   formale di Generation Exclusivity & Monotonicity generalizzata lungo
   una catena, non limitata a un singolo confine.
9. **`orchestrator_non_authority_attestation`** — ogni accettazione
   (Boot o Renew) richiede che l'Agent/TPM genuino abbia realmente
   prodotto la quote corrispondente; nessun trigger dell'Orchestrator, da
   solo, basta.
10. **`orchestrator_non_authority_migration`** — stessa proprietà per la
    migrazione: richiede entrambe le quote (sorgente e target) realmente
    prodotte.
11. **`migration_atomicity`** / **`migration_atomicity2`** — il ritiro
    della generazione sorgente e l'ammissione di quella destinazione (per
    la prima e la seconda migrazione rispettivamente) avvengono sempre
    nello stesso istante — mai una finestra intermedia con entrambe, o
    nessuna, live. Prova formale esplicita di Migration Atomicity, oltre
    alla garanzia già implicita nella semantica atomica delle regole
    Tamarin.

## Cronologia della costruzione del modello

Il modello non è stato definito correttamente al primo tentativo. Nel
corso dello sviluppo sono emersi cinque problemi tecnici distinti, di
due categorie: errori di fedeltà nella codifica delle regole (risolti
correggendo sintassi o struttura del modello), e problemi di
trattabilità computazionale della ricerca automatica (risolti riducendo
lo spazio di stati da esplorare).

1. **Verifica delle firme codificata per corrispondenza diretta di
   pattern**: la struttura iniziale delle regole non permetteva a
   Tamarin di derivare correttamente la chiave usata nella firma
   (`Failed to derive Variable(s): akSk`), un avviso che segnalava
   un'analisi potenzialmente inaffidabile. Risolto adottando il modulo
   standard `builtins: signing` (funzione `verify/3`, azione `Eq(...)`,
   `restriction Equality`), l'idioma raccomandato dalla documentazione
   di Tamarin per la verifica di firme.
2. **Contenuto del token codificato interamente all'interno della
   firma**: poiché `verify()` restituisce solo un valore booleano e mai
   il contenuto in chiaro, i campi del token non risultavano derivabili
   nei lemmi (`Failed to derive Variable(s): g`). Risolto trasmettendo
   ogni messaggio firmato come coppia `<testo in chiaro, firma>`,
   coerentemente anche con la struttura reale di `model.Token` nel
   codice Go, dove solo `SignatureV` è opaco.
3. **Falsificazione del lemma `fail_closed_requires_valid_attestation`
   in seguito all'estensione del modello con la Migrazione**: il lemma
   richiedeva sempre un evento `Accepted`, ma la migrazione produce
   invece `MigrationCompleted` — non un attacco, ma una formulazione del
   lemma non più coerente con l'ampliamento del modello. Corretto
   ammettendo entrambe le giustificazioni come vie legittime.
4. **Esplosione dello spazio di ricerca causata da regole prive di
   terminazione strutturale**: alcune regole (`Enforcement_CheckRouting`,
   poi rimossa; `Verifier_ChallengeRenew`; `Verifier_BeginMigration`)
   potevano essere applicate un numero indefinito di volte, portando la
   ricerca automatica a non terminare in tempi ragionevoli. Risolto sia
   eliminando la regola non necessaria alla dimostrazione (riformulando
   i lemmi coinvolti in termini di eventi naturalmente limitati), sia
   vincolando le operazioni ripetibili (rinnovo, migrazione) a un
   singolo utilizzo per istanza tramite fatti lineari dedicati.
5. **Isolamento della causa dei problemi di trattabilità**: per
   diagnosticare rapidamente il problema precedente senza rieseguire
   l'intera teoria a ogni tentativo, sono stati costruiti modelli
   progressivamente più piccoli, contenenti solo le regole strettamente
   necessarie al lemma sotto esame — tecnica standard nella verifica con
   Tamarin quando una teoria completa risulta intrattabile per la
   ricerca automatica.

I file `.spthy` risultanti da questo processo, e la struttura a più
teorie mirate che ne è derivata, sono descritti nella tabella in
apertura.

## Validità e affidabilità del modello

Tamarin non ha letto alcuna riga di `verifier.go`: verifica le regole
scritte nei file di questa cartella, una descrizione astratta che
intende rappresentare fedelmente
`agent.go`/`verifier.go`/`enforcement.go`. La dimostrazione matematica è
ineccepibile sul modello; non garantisce da sola che il modello
corrisponda al codice reale. Un modello scritto in modo eccessivamente
semplificato, o che ometta silenziosamente un controllo presente nel
codice, potrebbe "dimostrare sicuro" un sistema che, nella sua
implementazione reale, non lo è. È un limite riconosciuto della verifica
formale in generale, non una debolezza specifica di questo progetto.

### Il rischio: un modello può nascondere un'insicurezza reale

Nulla impedisce, né a un'IA né a un revisore umano, di scrivere un
modello Tamarin più debole del sistema reale, in modo che proprietà
false nel codice risultino vere nel modello. Non è un difetto dello
strumento: Tamarin dimostra esattamente ciò che gli viene chiesto di
dimostrare — il rischio risiede nello scollamento tra ciò che il modello
descrive e ciò che il codice effettivamente realizza.

### Come si verifica che non sia questo il caso

**1) Tracciabilità.** Ogni regola è annotata con la funzione Go
corrispondente (vedi la tabella sopra) e ogni semplificazione è
dichiarata esplicitamente nei commenti dei file — non ci sono controlli
"scomparsi silenziosamente": chi legge può confrontare riga per riga.

**2) Test di mutazione (eseguito e verificato in questo progetto — con
risultato empirico confermato, non solo previsto).** Per dimostrare che
il modello *reagisce* davvero a una vulnerabilità reale, non solo a
scenari "di comodo", è stata creata una copia deliberatamente difettosa
— [`ra5g_boot_renew_MUTATO_dimostrazione.spthy`](ra5g_boot_renew_MUTATO_dimostrazione.spthy)
— con un'unica modifica: il fatto `Pending` (che nel modello corretto è
**lineare**, consumabile una sola volta) reso **persistente**
(`!Pending`), simulando un bug realistico. Eseguendo `tamarin-prover` su
questa versione, il risultato è stato:

```
executability (exists-trace): verified (9 steps)
fail_closed_requires_valid_attestation (all-traces): verified (6 steps)
no_replay (all-traces): falsified - found trace (14 steps)
```

`no_replay` **è stato effettivamente falsificato**, con un attacco
concreto di 14 passi trovato automaticamente da Tamarin — la prova
pratica che il modello non è "addomesticato" per dire sempre "sicuro".

**3) Nessuna fiducia cieca.** Il modello, essendo scritto con assistenza
di un'IA, va trattato come qualunque altro artefatto prodotto in questo
modo nel progetto: **utile solo se accompagnato da una revisione umana
indipendente** che confronti le regole con il codice sorgente reale.

## TOCTOU-continuity — proprietà riconosciuta, non ancora formalizzata

A differenza degli altri cinque obiettivi, TOCTOU-continuity non è
trattata come un gap da colmare in un prossimo file `.spthy`, ma come un
**confine architetturale riconosciuto**, per il motivo spiegato sotto.

### La definizione, e la capacità dell'attaccante che la genera

Il paper la introduce a partire da una capacità dell'avversario che
dichiara esplicitamente **distinta** dal modello Dolev-Yao puro (§III-B):

> *"Att may compromise Π between two attestation events and attempt to
> conceal this from the subsequent quote (e.g., by reverting to a
> known-good state before responding to a challenge). This capability is
> **temporal/stateful rather than purely message-level**, and is what
> distinguishes our model from a plain challenge-response DY analysis."*

### Il paper stesso la dichiara fuori scope del design a livello di protocollo

Nella Tabella I del paper (mappa obiettivo-avversario → meccanismo), la
riga corrispondente recita:

> *"Concealed transient compromise → **Out of scope of §V; addressed at
> the hardware measurement layer**"*

§V è la sezione che descrive esattamente i meccanismi che questo
progetto formalizza in Tamarin (nonce, quote, token, generation-link
certificate, burn record). **Il paper stesso non pretende di risolvere
TOCTOU-continuity a quel livello** — la demanda a un layer architetturale
diverso (misurazione hardware continua), che né il paper né questo
progetto sviluppano oltre la menzione.

### Perché un protocollo a sfida-risposta non può, da solo, chiuderla

Ogni protocollo di attestazione a sfida-risposta — il nostro compreso —
verifica lo stato della macchina in un **istante puntuale**: quando
arriva la quote, il TPM firma ciò che misura *in quel momento*. Non
esiste, nel meccanismo, alcuna informazione su cosa sia accaduto **tra**
una quote e la successiva. Un attaccante che compromette il livello
software (mai la chiave TPM — esclusa per ipotesi dal modello di
minaccia), agisce, e poi ripristina i PCR a valori "buoni" prima della
prossima sfida produce una quote crittograficamente **perfetta**: firma
autentica, digest coincidente col Golden Measurement. Nessun confronto
punto-per-punto tra "quote attuale" e "policy di riferimento" può
rivelare quella finestra, perché non lascia traccia nell'unico dato che
il protocollo osserva.

### Riflesso preciso nell'implementazione Go attuale

`verifyQuoteLocked` confronta **staticamente** `PCRDigest` con il Golden
Measurement a ogni rinnovo discreto — un meccanismo *a scatti*
(snapshot-based), non una misurazione continua. Nessun meccanismo, né
nel codice né nel modello Tamarin, copre l'**intervallo** tra un rinnovo
e il successivo — solo i due istanti agli estremi. Non è un'omissione:
è coerente con quanto il paper stesso ammette non essere nello scope del
design a livello di protocollo.

### Perché Tamarin, così com'è, non può nemmeno esprimere la proprietà

La nostra crittografia simbolica assume che l'attaccante non conosca mai
`~akSk` — l'unico modo di forgiare una firma. Ma TOCTOU-continuity
riguarda un attaccante che **non tocca affatto la chiave**: compromette
solo ciò che sta sopra il confine hardware. `'golden'` è una costante
pubblica **fissa**: non rappresenta il *processo* di misurazione nel
tempo, solo il suo output atteso confrontato per uguaglianza. Non esiste,
nel modello attuale, alcun modo di rappresentare "lo stato è stato
alterato e poi ripristinato" — servirebbe modellare la misurazione come
**sequenza** nel tempo (un log), non un valore statico.

### Requisiti per un'eventuale formalizzazione futura

- **A livello di modello formale**: un evento esplicito di
  compromissione temporanea (distinto da un key-leak permanente), e una
  rappresentazione della misurazione come sequenza continua anziché come
  valore statico — un'estensione concettualmente diversa da quanto il
  modello attuale realizza, più vicina alla verifica di proprietà
  storiche/stateful che all'analisi di scambio di messaggi.
- **A livello di implementazione Go**: un meccanismo di misurazione
  realmente continua (un log append-only, sul modello IMA citato nel
  paper, o un monitoraggio hardware continuo) — un cambiamento
  architetturale, non una correzione puntuale di `verifyQuoteLocked`.

## Cosa NON è ancora coperto dalla verifica formale

- **TOCTOU-continuity** — confine architetturale riconosciuto, vedi la
  [sezione dedicata](#toctou-continuity--proprietà-riconosciuta-non-ancora-formalizzata)
  sopra.
- **Freshness in senso stretto (limite di tempo quantitativo)** — `no_replay`
  copre solo la componente di non-riuso del nonce; un vero limite di
  staleness (TTL) non è esprimibile nella logica simbolica di Tamarin.
- **Il TTL sulle migrazioni pendenti** (`DefaultMigrationTTL`) — non
  modellato, stesso motivo.
- **La certificazione EK→AK** — la stessa assunzione dichiarata nel
  codice Go: il modello lascia che la AK sia generata onestamente in una
  regola di setup, mai sotto controllo dell'attaccante.
- **Bug a livello di *implementazione*** (es. il blocco dei simulatori
  TPM concorrenti, o la collisione in `MigrationSourceBoundNonce`): la
  verifica formale opera al livello del *protocollo*, non
  dell'implementazione Go.

## Come eseguire i modelli

```bash
cd docs/verif/tamarin
tamarin-prover ra5g_boot_renew.spthy --prove
tamarin-prover ra5g_revocation.spthy --prove
tamarin-prover ra5g_migration_single.spthy --prove
tamarin-prover ra5g_generation_exclusivity_chain.spthy --prove
tamarin-prover ra5g_orchestrator_authority.spthy --prove
tamarin-prover ra5g_orchestrator_authority_migration.spthy --prove
```

Per output lunghi, reindirizza su file:

```bash
tamarin-prover NOMEFILE.spthy --prove > output.txt 2>&1
```

Installazione di Tamarin (richiede GHC/Haskell e Maude come prerequisiti,
raccomandato tramite Homebrew anche su WSL/Ubuntu):

```bash
brew install tamarin-prover/tap/tamarin-prover
```
