# 05 — Stato del progetto, limiti noti, prossimi passi

## Cosa è implementato e verificato

| Elemento | Stato |
|---|---|
| Bootstrap (Fase 1 del sequence diagram) | ✅ Implementato, testato (unità + end-to-end con TPM simulato) |
| Continuous Attestation / rinnovo lease (Fase 2) | ✅ Implementato, testato |
| Rilevamento replay attack | ✅ Implementato, testato |
| Revoca immediata del routing dopo un burn (canale Verifier→Enforcement) | ✅ Implementato, testato — colma il gap "Revoca Immediata Routing" della Fase 4 del diagramma |
| Comportamento Fail-Closed (token scaduto/non valido/istanza mai vista) | ✅ Implementato, testato |
| Context-binding del nonce (tag Boot/Renew/Migrate legato crittograficamente al nonce firmato) | ✅ Implementato, testato |
| Integrazione con TPM 2.0 reale via `google/go-tpm-tools`, verificata anche su simulatore software | ✅ Funzionante end-to-end |

## Cosa NON è implementato

### Fase 3 — Migrazione Cooperativa

Il sequence diagram del protocollo descrive un flusso in cui:

1. Il Verifier emette una challenge di migrazione (`nonce n_mig`) legata
   sia all'istanza uscente sia all'host di destinazione.
2. L'istanza uscente produce `Q_src` (quote con tag `"migrate"`, già
   supportato nel codice tramite `model.ContextTagMigrate`, ma non ancora
   usato in alcun flusso reale).
3. Una nuova istanza viene avviata sull'host target e produce `Q_dst`,
   usando **lo stesso** `n_mig`.
4. Il Verifier esegue un **Atomic Commit**: valida entrambe le quote
   correlate dallo stesso nonce, poi in un'unica operazione logica
   ritira la fiducia dalla generazione uscente (`g_0`) e la concede alla
   nuova (`g_1`).
5. Viene rilasciato un `GenerationLinkCert` (già definito in `model.go`,
   mai popolato) che lega crittograficamente le due generazioni.

**Cosa manca concretamente nel codice:** un metodo tipo
`Verifier.BeginMigration(instanceID, targetHost) (nonce, error)`, la
logica di validazione dual-quote con commit atomico, l'emissione del
`GenerationLinkCert`, e un secondo `Agent` (per l'istanza target) nello
scenario di test/demo.

**Buona notizia architetturale:** l'Enforcement Plane è già pronto a
sostenere questo flusso senza modifiche — `UpdateRoutingRules` già
sostituisce atomicamente l'intera regola di routing sotto lock (vedi
`enforcement.go`), quindi "ritira `g_0`, ammetti `g_1`" funzionerebbe già
oggi se il Verifier gli passasse il Token corretto per la nuova
generazione. Il lavoro mancante è tutto a monte, nel Verifier.

**Domanda aperta, non ancora modellata:** se ogni host ha un TPM fisico
distinto (verosimile), la AK dell'host target va registrata presso il
Verifier separatamente — quando, e con quale meccanismo di provisioning?
Non risolto né dal sequence diagram né dal codice attuale.

### Gap di provisioning EK→AK

Il Verifier, in `RegisterInstance`, si fida "per definizione" della
chiave pubblica AK che riceve durante l'onboarding — non esiste alcuna
verifica che quella chiave provenga davvero da un TPM genuino e non
esportabile. In un deployment reale, questo richiederebbe:

1. Ogni TPM ha una **Endorsement Key (EK)** incisa in fabbrica, con un
   certificato firmato dal produttore del chip.
2. L'AK viene creata dentro il TPM (non esportabile) e **certificata**
   legandola crittograficamente all'EK tramite una challenge-response
   (`TPM2_ActivateCredential`), tipicamente gestita da una CA di
   attestazione dedicata.
3. Solo dopo questo enrollment il Verifier può fidarsi che l'AK pubblica
   "parla per" un TPM reale.

Questo passaggio non esiste nel codice attuale: `client.AttestationKeyRSA`
(usata in `rot.go`) crea l'AK ma non esegue alcuna certificazione EK→AK.
È un limite esplicitamente documentato nei commenti di `rot.go` fin dalla
sua introduzione, non una svista.

### Nonce/handover terminologia — Token rinnovato vs Token esteso

Il sequence diagram usa la dicitura "Estendi Scadenza Token T_g" per il
rinnovo — suggerendo che lo *stesso* token venga esteso. Il codice attuale
**emette sempre un nuovo Token** (nuova firma, nuovo `IssuedAt`) invece di
estendere la scadenza di quello esistente. Funzionalmente equivalente
oggi (l'Enforcement sostituisce comunque atomicamente la regola), ma se
in futuro servisse un audit trail preciso ("quante volte è stato
rinnovato T_g"), converrebbe dare al Token un identificativo stabile che
sopravviva ai rinnovi.

## Suggerimento sull'ordine di lavoro futuro

Se si riprende lo sviluppo, l'ordine naturale è:

1. **Fase 3 (Migrazione)** — è il pezzo funzionale mancante più grande,
   e può appoggiarsi sia sul context-binding del nonce (già pronto per il
   tag `Migrate`) sia sul canale di revoca immediata (già pronto per
   notificare l'Enforcement in caso di fallimento della migrazione) senza
   ulteriori modifiche a quei due meccanismi.
2. **Provisioning EK→AK** — indipendente dalla Fase 3, ma prerequisito
   per qualunque deployment su hardware reale al di fuori di un ambiente
   di test.
3. **Livello di trasporto (gRPC)** — esplicitamente rimandato fin dal
   documento di analisi originale ("nelle fasi iniziali dell'implementazione,
   NON sviluppare l'infrastruttura di rete gRPC/HTTP"); il codice attuale
   resta volutamente in-process per isolare e verificare la logica di
   business prima di introdurre la complessità di rete.
