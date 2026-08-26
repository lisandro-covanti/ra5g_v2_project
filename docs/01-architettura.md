# 01 — Architettura

## Le 5 entità del protocollo

Il protocollo RA5G, come definito nel documento di analisi originale,
individua 5 entità con gradi di fiducia diversi. Questa separazione è il
principio guida di tutta l'architettura del codice: **ogni entità è un
package Go distinto**, e nessun package dipende da un altro se non
attraverso la relazione di fiducia che l'analisi originale gli assegna.

| Entità | Grado di fiducia | Package | Tocca il TPM? |
|---|---|---|---|
| **Verifier ($V$)** | Completamente fidato | `verifier` | No — riceve solo evidenza già firmata |
| **Attestation Agent ($A$)** | Minimo, nessuna autorità di firma propria | `agent` | Sì, tramite l'interfaccia `rot.RootOfTrust` |
| **Prover ($\Pi$)** | Non fidato (è l'istanza VNF/CNF stessa) | — (rappresentato implicitamente dallo stato dei PCR) | — |
| **Enforcement Plane ($E$)** | Fidato per l'esecuzione delle regole di routing | `enforcement` | No — mai, in nessuna versione del codice |
| **Orchestrator ($Orch$)** | OUT OF TCB, non fidato | — (rappresentato in `main.go` dal semplice avvio del ciclo di vita) | No |

Un punto architetturale verificato più volte durante lo sviluppo:
**l'Enforcement Plane non ha mai avuto bisogno di importare nulla legato
al TPM**, in nessuna fase del progetto. È la prova pratica che separare
"chi decide se fidarsi" (Verifier) da "chi applica la decisione"
(Enforcement) funziona: passare da una simulazione software a un vero
TPM per Agent/Verifier non ha richiesto toccare `enforcement.go`.

## Il package `rot` — perché esiste e cosa risolve

Il package `rot` (Root of Trust) è stato introdotto per una ragione
precisa, discussa esplicitamente durante lo sviluppo: **isolare ogni
dipendenza da una libreria TPM concreta dietro un'interfaccia Go**.

```go
type RootOfTrust interface {
    PublicKey() crypto.PublicKey
    ExtendPCR(pcrIndex int, event []byte) error
    ReadPCRs(pcrSelection []int) (map[int][]byte, error)
    Attest(pcrSelection []int, nonce []byte) (*attestpb.Attestation, error)
    Close() error
}
```

`agent.go` dipende **solo** da questa interfaccia, mai dal tipo concreto
`rot.TPM2RootOfTrust` né, tanto meno, direttamente da `google/go-tpm-tools`.
Due conseguenze pratiche, entrambe verificate concretamente nel progetto:

1. **Sostituibilità.** Passare a un TPM reale invece del simulatore
   software è cambiare una riga in `main.go` (`rot.OpenSimulator()` →
   `rot.OpenDevice()`), senza toccare `agent.go`, `verifier.go`, o la
   logica di business.
2. **Testabilità a costo zero.** `agent/agent_test.go` implementa un
   `fakeRootOfTrust` che soddisfa la stessa interfaccia restituendo dati
   fittizi istantanei: i test di `agent.go` durano microsecondi, non i
   ~30ms che costa ogni test che apre un vero simulatore TPM (vedi
   [`04-testing.md`](04-testing.md)).

## Modello dati (`model`)

Il package `model` contiene solo tipi dati e le funzioni di codifica
canonica usate per le firme — nessuna logica di business, per evitare
import ciclici (tutti gli altri package dipendono da `model`, mai il
contrario).

- **`QuotePayload`** — l'evidenza prodotta dall'Agent. In Fase 2 non
  porta più un digest/firma "fatti in casa" (come in una prima versione
  di prototipazione): incapsula opaco un `AttestationBlob` (la vera
  struttura TPM standard `TPMS_ATTEST`+`TPMT_SIGNATURE`, serializzata
  Protobuf da `google/go-tpm-tools`), più i metadati applicativi
  `InstanceID`, `Generation`, `Tag`, `Nonce`, `TargetHost` (quest'ultimo
  usato solo nella quote di migrazione dell'istanza uscente, vedi Fase 3
  sotto).
- **`ContextTag`** — identifica il tipo di operazione per cui una quote
  è stata richiesta (`Boot`, `Renew`, `Migrate`). Vedi
  [`03-problemi-e-soluzioni.md`](03-problemi-e-soluzioni.md#context-binding-del-nonce)
  per il problema di sicurezza che risolve.
- **`ContextBoundNonce(tag, instanceID, generation, nonce)`** — la
  codifica canonica che lega insieme questi quattro valori in un unico
  digest, effettivamente firmato dal TPM al posto del nonce nudo. Usata
  per Bootstrap, Renew, e per la quote dell'istanza ENTRANTE in una
  migrazione.
- **`MigrationSourceBoundNonce(instanceID, oldGeneration, nonce, targetHost)`**
  — variante usata SOLO dalla quote dell'istanza USCENTE durante una
  migrazione: lega anche l'host di destinazione, non solo tag/instanceID/
  generation/nonce. Vedi
  [`06-fase3-migrazione.md`](06-fase3-migrazione.md) per il dettaglio, e
  [`03-problemi-e-soluzioni.md`](03-problemi-e-soluzioni.md#la-collisione-in-migrationsourceboundnonce)
  per un bug reale scoperto da un test su questa funzione.
- **`Token`** — il "visto d'accesso a tempo" che il Verifier emette per
  l'Enforcement Plane, firmato con la chiave operativa del Verifier
  (`sk_V`, RSA software — **non** TPM-backed, per una ragione precisa:
  vedi sotto).
- **`BurnRecord`** — registro permanente di revoca di una generazione.
- **`GenerationLinkCert`** — firmato da `CompleteMigration` (Fase 3) al
  termine di una migrazione riuscita: lega crittograficamente la
  generazione uscente (`OldGeneration`) a quella entrante
  (`NewGeneration`), insieme a `MigNonce` e `TargetHost`.

## Perché `sk_V` (la chiave del Verifier) resta RSA software, non TPM

Una domanda legittima leggendo il codice: se l'obiettivo è "crittografia
vera basata su TPM", perché il Verifier firma i Token con una semplice
chiave RSA generata in RAM (`cryptoutil.GenerateKeyPair`), non con un
TPM?

Perché il Verifier **non è l'entità il cui stato va attestato**. Il TPM
serve a legare una chiave a un *hardware fisico specifico*, per poter
dire "questa firma prova che proviene da QUESTA macchina, nel suo stato
attuale". Il Verifier è un servizio applicativo ordinario (potenzialmente
ridondato, in esecuzione su più nodi, dietro un bilanciatore) — non ha
senso vincolare la sua chiave operativa a un singolo chip TPM. È l'Agent,
non il Verifier, ad aver bisogno di un Root of Trust hardware, perché è
l'Agent a dover provare "sono davvero questa macchina, in questo stato".

## Confini di fiducia — cosa NON è (ancora) risolto

Il codice attuale presume che, quando il Verifier riceve una chiave
pubblica AK durante l'onboarding (`RegisterInstance`, e — dalla Fase 3 —
anche `CompleteMigration` per l'host target), quella chiave provenga
davvero da un TPM genuino. Questa fiducia è oggi **assunta, non
verificata**: manca il passo di certificazione EK→AK (challenge
`TPM2_ActivateCredential` contro un certificato EK di fabbrica) che, in
un deployment reale, proverebbe che l'AK è davvero vincolata
all'hardware e non è una semplice chiave software generata da un
attaccante. È un limite noto, documentato anche nei commenti di
`rot.go`, e discusso in dettaglio in
[`05-roadmap.md`](05-roadmap.md#gap-di-provisioning-ekak).
