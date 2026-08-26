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
| Migrazione Cooperativa (Fase 3): Q_src/Q_dst, Atomic Commit, GenerationLinkCert | ✅ Implementato, testato — vedi [`06-fase3-migrazione.md`](06-fase3-migrazione.md) |
| Integrazione con TPM 2.0 reale via `google/go-tpm-tools`, verificata anche su simulatore software | ✅ Funzionante end-to-end |

## Cosa NON è implementato

### Fase 3 — Migrazione Cooperativa: IMPLEMENTATA

A partire da questa versione del progetto, la Fase 3 è implementata e
testata — vedi [`06-fase3-migrazione.md`](06-fase3-migrazione.md) per i
dettagli su API, scelte di sicurezza e come è garantita l'atomicità del
commit. Restano aperti solo i tre limiti descritti in fondo a quel
documento (provisioning AK del target host, trasporto di rete, timeout
su una migrazione pendente mai completata).

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

Con la Fase 3 ora implementata, l'ordine naturale per il lavoro
successivo è:

1. **Provisioning EK→AK** — prerequisito per qualunque deployment su
   hardware reale al di fuori di un ambiente di test; riguarda sia
   `RegisterInstance` sia il parametro `newAKPublicKey` di
   `CompleteMigration`.
2. **Livello di trasporto (gRPC)** — esplicitamente rimandato fin dal
   documento di analisi originale ("nelle fasi iniziali dell'implementazione,
   NON sviluppare l'infrastruttura di rete gRPC/HTTP"); il codice attuale
   resta volutamente in-process per isolare e verificare la logica di
   business prima di introdurre la complessità di rete.
