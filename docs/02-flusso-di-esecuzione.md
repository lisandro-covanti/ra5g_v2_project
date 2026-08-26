# 02 — Flusso di esecuzione, fase per fase

Questo documento descrive cosa succede concretamente nel codice — quali
funzioni vengono chiamate, in quale ordine, con quali dati — per ciascuna
fase implementata. Corrisponde a ciò che `main.go` esegue e stampa a
video, e a ciò che `main_test.go` verifica automaticamente.

## Setup (prima di ogni fase)

```
verifier.New()                              → crea sk_V/pk_V (RSA software)
rot.OpenSimulator()                         → apre un TPM 2.0 simulato in-process
rot.NewTPM2RootOfTrust(tpmConn)             → crea/carica la Attestation Key (AK) nel TPM
agent.NewAgent(instanceID, root)             → crea l'Agent, legato a quel RootOfTrust
a.ExtendPCR(0, "genuine-bootloader-v1.4")    → misura un boot "genuino" nel PCR 0
a.ExtendPCR(1, "genuine-os-image-...")       → misura nel PCR 1
root.ReadPCRs(rot.FullPCRSelection())        → legge lo stato PCR corrente dal TPM
combinedPCRDigest(pcrValues, pcrSelection)    → calcola il Golden Measurement
v.RegisterInstance(instanceID, ak.PublicKey(), golden)  → onboarding, fuori dal path critico
enforcement.New(v.PublicKey())               → crea l'Enforcement, gli passa pk_V
v.OnRevoke(func(id, gen) { e.Revoke(id, gen) })         → collega il canale di revoca immediata
```

Nota sulla selezione PCR: `rot.FullPCRSelection()` restituisce **tutti**
i PCR del banco SHA-256 (tipicamente 24), non un sottoinsieme scelto da
noi. Il motivo è discusso in dettaglio in
[`03-problemi-e-soluzioni.md`](03-problemi-e-soluzioni.md#la-libreria-quota-sempre-tutti-i-pcr)
— in breve: `client.Key.Attest()` non offre alcun modo di restringere la
quote a un sottoinsieme, quindi il Golden Measurement deve essere
calcolato sugli stessi PCR che la quote reale coprirà, altrimenti il
confronto fallisce sempre.

## Fase 1 — Bootstrap (generation g = 0)

```
nonce0 := v.GenerateNonce(instanceID)
quote0 := a.GetTPMQuote(0, nonce0, pcrSelection, model.ContextTagBoot)
    │
    ├─ boundNonce := model.ContextBoundNonce(ContextTagBoot, instanceID, 0, nonce0)
    └─ attestation := a.RoT.Attest(pcrSelection, boundNonce)   ← vero TPM2_Quote

ok := v.VerifyQuote(instanceID, *quote0, nonce0, model.ContextTagBoot)
    │
    ├─ 1. quote.Tag == expectedTag?                     (context-binding)
    ├─ 2. nonce corrisponde alla challenge pendente?     (bookkeeping applicativo)
    ├─ 3. nonce non è già stato usato?                   (anti-replay)
    ├─ 4. server.VerifyAttestation(...) con Nonce=boundNonce  (firma TPM standard)
    ├─ 6. PCRDigest estratto dal TPMS_ATTEST == Golden Measurement?
    └─ 7. generation >= quella live per l'istanza?       (monotonicità)

token0 := v.IssueToken(instanceID, 0)        → firmato con sk_V, TTL = 30s
e.UpdateRoutingRules(token0)                  → Enforcement valida firma+scadenza, ammette il routing
e.IsRoutingAllowed(instanceID)                → true
```

Alla fine di questa fase, l'istanza è "live" alla generazione 0 e il
traffico verso di essa è instradato.

## Fase 2 — Continuous Attestation (rinnovo, stessa generazione)

Identico schema del Bootstrap, con due differenze:

- Il tag passato è `model.ContextTagRenew`, non `ContextTagBoot` — il
  Verifier si aspetta esplicitamente una risposta di rinnovo, non un
  nuovo bootstrap.
- Il controllo di monotonicità (punto 7 sopra) ammette una generazione
  **uguale** a quella già live (non solo strettamente maggiore): è
  esattamente il caso "stessa generazione, lease rinnovata".

```
nonce1 := v.GenerateNonce(instanceID)
quote1 := a.GetTPMQuote(0, nonce1, pcrSelection, model.ContextTagRenew)
ok := v.VerifyQuote(instanceID, *quote1, nonce1, model.ContextTagRenew)
token1 := v.IssueToken(instanceID, 0)         → nuovo Token, nuovo IssuedAt/ExpiresAt
e.UpdateRoutingRules(token1)                   → sostituzione atomica della regola precedente
```

## Replay Attack (rilevamento + revoca immediata)

Questo scenario dimostra due proprietà insieme: il rilevamento del
replay (che esisteva già dalla prima versione del codice) e il **canale
di revoca immediata** (aggiunto successivamente, vedi
[`03-problemi-e-soluzioni.md`](03-problemi-e-soluzioni.md#nessuna-notifica-attiva-verso-lenforcement)).

```
replayOK := v.VerifyQuote(instanceID, *quote1, nonce1, model.ContextTagRenew)
    │
    └─ fallisce al punto 3 (anti-replay): nonce1 è già in usedNonces
       → v.burnLocked(instanceID, 0, "replay attack: nonce già consumato")
       → verifyQuoteLocked restituisce (false, 0, wasRevoked=true)
       → VerifyQuote chiama v.fireRevokeHooks(instanceID, 0)
       → l'hook registrato in Setup chiama e.Revoke(instanceID, 0)
       → e.Revoke nega IMMEDIATAMENTE il routing (non aspetta il TTL)

e.IsRoutingAllowed(instanceID)   → false, SUBITO, senza attese
v.BurnRecords(instanceID)         → 1 record, motivo "replay attack: nonce già consumato"
v.IssueToken(instanceID, 0)       → errore: generazione bruciata
```

Il dettaglio implementativo per cui questo funziona senza deadlock (la
notifica agli hook avviene **dopo** che il mutex del Verifier è stato
rilasciato, mai mentre è ancora acquisito) è spiegato per esteso in
[`03-problemi-e-soluzioni.md`](03-problemi-e-soluzioni.md#nessuna-notifica-attiva-verso-lenforcement).

## Fail-Closed Default

Due scenari, entrambi senza bisogno di alcuna quote TPM:

```
// Token scaduto e con firma non valida
expiredToken := &model.Token{ExpiresAt: <nel passato>, SignatureV: <non valida>}
e.ValidateToken(expiredToken)     → false (fallisce sia il controllo scadenza sia quello firma)
e.UpdateRoutingRules(expiredToken) → nega esplicitamente il routing

// Istanza mai attestata
e.IsRoutingAllowed("istanza-mai-vista")  → false per DEFAULT, non serve alcuna azione esplicita
```

Il principio verificato qui: l'assenza di una regola di routing valida
non equivale MAI a "consentito" — il default, in ogni ramo del codice
che decide se instradare traffico, è negare.

## Fase 3 — Migrazione Cooperativa (g_0 → g_1)

A differenza di Bootstrap/Renew (dove il Verifier coordina un solo
scambio challenge/risposta), la Migrazione coinvolge DUE istanze fisiche
distinte — sorgente e target, su TPM diversi — coordinate in tre chiamate
separate.

```
// --- Lato SORGENTE (istanza g_0, in esecuzione) ---
nMig := v.BeginMigration(instanceID, targetHost)
    └─ richiede che l'istanza sia attualmente live; genera n_mig e lo
       registra come migrazione pendente, con scadenza
       now + DefaultMigrationTTL (vedi sotto)

qSrc := srcAgent.GetMigrationSourceQuote(oldGeneration, nMig, pcrSelection, targetHost)
    │
    ├─ boundNonce := model.MigrationSourceBoundNonce(instanceID, oldGeneration, nMig, targetHost)
    └─ attestation := srcAgent.RoT.Attest(pcrSelection, boundNonce)   ← vero TPM2_Quote, lega ANCHE targetHost

srcOK := v.ValidateMigrationSource(instanceID, *qSrc)
    │
    ├─ 1. la migrazione pendente non è scaduta? (DefaultMigrationTTL)
    ├─ 2. quote.Tag == Migrate?
    ├─ 3. quote.Generation == generazione live al momento di BeginMigration?
    ├─ 4. quote.TargetHost == quello di BeginMigration?
    ├─ 5. nonce == n_mig?
    ├─ 6. server.VerifyAttestation(...) con Nonce=boundNonce
    └─ 7. PCRDigest estratto == Golden Measurement della sorgente?
       → su successo: pending.SourceValidated = true (NESSUNA mutazione
         di v.live ancora: la fiducia non è concessa finché non arriva
         anche Q_dst)

// --- Lato TARGET (nuova istanza g_1, su un host diverso) ---
qDst := dstAgent.GetTPMQuote(newGeneration, nMig, pcrSelection, model.ContextTagMigrate)
    │
    └─ usa ContextBoundNonce GENERICO (non MigrationSourceBoundNonce):
       l'istanza target non "acconsente a migrare verso un host", è già
       lì fisicamente — attesta solo sé stessa in una nuova generazione

token, cert, ok := v.CompleteMigration(instanceID, newGeneration, *qDst, dstAK, dstGolden)
    │
    ├─ richiede pending.SourceValidated == true (Atomic Migration:
    │  Dual-Sided Authorization — nessuna nuova generazione senza
    │  consenso PROVATO della sorgente)
    ├─ valida Q_dst (stesso schema di VerifyQuote)
    └─ ATOMIC COMMIT, tutto sotto un solo Lock/Unlock:
       1. registrations[instanceID] aggiornata con AK/Golden del target
       2/3. issueTokenLocked sovrascrive v.live[instanceID] con g_1
            (ritira implicitamente g_0, ammette g_1 — mai un istante
            intermedio con entrambe le generazioni live)
       4. emette e firma il GenerationLinkCert (g_0 → g_1, target_host)

e.UpdateRoutingRules(token)   → sostituzione atomica della regola di routing
```

Le due scelte di sicurezza non ovvie da questo solo schema — **Q_src non
valida brucia la generazione corrente**, **Q_dst non valida aborta senza
penalizzare la sorgente** — e i dettagli sul TTL della migrazione
pendente sono spiegati in
[`06-fase3-migrazione.md`](06-fase3-migrazione.md), non ripetuti qui.

## Cosa NON è (ancora) coperto da questo flusso

Il **provisioning EK→AK** (certificazione che un'AK provenga davvero da
un TPM genuino, sia per `RegisterInstance` sia per `CompleteMigration`) e
il **livello di trasporto di rete** (il progetto resta volutamente
in-process) restano aperti — vedi [`05-roadmap.md`](05-roadmap.md).
