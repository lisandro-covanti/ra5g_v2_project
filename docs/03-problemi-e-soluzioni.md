# 03 — Problemi affrontati e soluzioni adottate

Questo documento racconta, in ordine cronologico, i problemi **reali**
incontrati passando da una simulazione crittografica software a
un'integrazione vera con `google/go-tpm`/`google/go-tpm-tools`, e perché
le soluzioni adottate sono quelle che sono. Non è un elenco teorico: ogni
punto qui sotto è stato scoperto compilando o eseguendo davvero il
codice, non previsto a tavolino.

## Scelta della libreria: perché `google/go-tpm-tools`, non solo `go-tpm`

`google/go-tpm` (il pacchetto `legacy/tpm2`) espone le primitive TPM2 a
basso livello (`tpm2.Quote`, `tpm2.CreatePrimary`...) — è una mappatura
quasi 1:1 dello standard TCG. Usarlo da solo avrebbe richiesto
ricostruire a mano l'intera logica di: creazione della Attestation Key
con il template corretto, lettura PCR, costruzione del `TPMS_ATTEST`,
parsing della firma.

`google/go-tpm-tools` (i package `client`/`server`/`simulator`) è
costruito **sopra** `go-tpm` proprio per il caso d'uso di questo
progetto — "attesta lo stato PCR di una macchina verso un verifier
remoto" — ed è la libreria che Google stessa usa per l'attestazione delle
Shielded VM/Confidential Space su GCE. `client.Key.Attest()` e
`server.VerifyAttestation()` incapsulano correttamente l'intero ciclo
quote→verifica in due chiamate, riducendo drasticamente la superficie di
codice "fatta in casa" che potrebbe contenere errori di sicurezza
sottili. Per questo è la scelta di libreria principale, con `legacy/tpm2`
usato solo per due operazioni specifiche non coperte da `go-tpm-tools`
(`PCREvent` per estendere i PCR, `DecodeAttestationData` per estrarre il
PCRDigest grezzo — vedi sotto).

## Isolamento dietro un'interfaccia (`rot.RootOfTrust`)

**Problema:** legare `agent.go` direttamente ai tipi concreti di
`google/go-tpm-tools` avrebbe reso il codice di business dipendente da
una libreria specifica — un problema esplicitamente sollevato durante lo
sviluppo: "questo codice userà API vendor-neutral, o sarà legato a
un'implementazione specifica?"

**Soluzione:** package `rot` dedicato, con l'interfaccia `RootOfTrust`
(vedi [`01-architettura.md`](01-architettura.md)) come unico contratto
visto da `agent.go`. La libreria concreta (`google/go-tpm-tools`) resta
confinata dentro `rot/rot.go`. Beneficio verificato concretamente: i test
di `agent.go` (`agent_test.go`) usano un `fakeRootOfTrust` che non tocca
mai un TPM, reale o simulato.

## `tpm2.OpenTPM` ha firme diverse per piattaforma

**Sintomo:**
```
rot\rot.go:106:27: too many arguments in call to tpm2.OpenTPM
    have (string)
    want ()
```
compilando su Windows, dopo aver scritto `OpenDevice(path string)` che
chiamava `tpm2.OpenTPM(path)`.

**Causa:** `go-tpm` implementa `OpenTPM` con build tag diversi per
piattaforma. Su Linux accetta un path opzionale al device node
(`/dev/tpmrm0`); su Windows l'accesso al TPM avviene sempre tramite il
servizio di sistema TBS (TPM Base Services), che non ha un path — la
funzione, su quella piattaforma, non accetta argomenti.

**Soluzione:** `rot.OpenDevice()` ora non accetta più un parametro
`path`, chiama `tpm2.OpenTPM()` senza argomenti. Su Linux questo usa il
device di default del sistema; su Windows apre TBS. Se in futuro servisse
un path Linux esplicito, andrebbe introdotto con un file `_linux.go` a
parte (build-tag-based), non riscrivendo la firma cross-platform.

## `(*client.Key).Close()` non restituisce un errore

**Sintomo:**
```
rot\rot.go:200:12: t.ak.Close() (no value) used as value
```

**Causa:** un'assunzione sbagliata scrivendo la prima versione del
codice — `Close()` su `*client.Key` in questa versione della libreria è
un semplice metodo di rilascio risorse senza valore di ritorno, non
`Close() error` come altri `Close()` del progetto (es. quello della
connessione TPM).

**Soluzione:** in `TPM2RootOfTrust.Close()`, `t.ak.Close()` viene
chiamato come istruzione a sé, non come espressione di cui controllare
l'errore.

## L'event log viene letto automaticamente dal sistema operativo, e fallisce fuori da Linux

**Sintomo:**
```
2026/08/25 18:25:54 rot: Attest fallito: failed to retrieve TCG Event Log:
    failed to get event log: only Linux supported
```

**Causa:** `client.Key.Attest()`, se il campo `AttestOpts.TCGEventLog`
viene lasciato al suo valore di default (`nil`), tenta
**automaticamente** di leggere l'event log di boot dal sistema operativo
ospite (su Linux, da `/sys/kernel/security/tpm0/binary_bios_measurements`).
Quella funzione di lettura è implementata solo per Linux nella libreria:
su Windows (l'ambiente su cui il progetto è stato effettivamente
compilato ed eseguito) fallisce sempre, anche usando il simulatore
software (che comunque non avrebbe un vero event log di sistema coerente
da offrire).

**Soluzione:** `rot.go` passa esplicitamente `TCGEventLog: []byte{}` (uno
slice **vuoto ma non `nil`**) — questo soddisfa il controllo "è stato
fornito un valore" e disattiva il tentativo di lettura automatica dal SO.
Prezzo della scelta: l'`Attestation` prodotta non porta un vero TCG event
log; accettabile per questo prototipo, dato che la logica applicativa
valuta il Golden Measurement sul `PCRDigest` estratto dal `TPMS_ATTEST`,
non sul contenuto dell'event log.

## La libreria quota sempre TUTTI i PCR

**Sintomo:** `VerifyQuote(gen=0): false` al primo bootstrap, senza alcun
errore esplicito — il confronto tra Golden Measurement e digest reale
falliva sempre.

**Causa:** un'assunzione sbagliata più insidiosa della precedente:
`client.Key.Attest()` **non offre alcun modo di restringere la quote a
un sottoinsieme di PCR** — `AttestOpts` espone solo `Nonce` e
`TCGEventLog`, nessun campo di selezione PCR. La quote prodotta copre
**sempre** l'intero banco SHA-256 (tipicamente 24 PCR), indipendentemente
da cosa veniva passato come `pcrSelection` alle funzioni del progetto. Il
Golden Measurement, nella prima versione del codice, veniva invece
calcolato solo sui PCR 0 e 1 (quelli effettivamente estesi in `main.go`)
— un digest calcolato su un sottoinsieme diverso da quello che il TPM
firma davvero, quindi sempre diverso, anche in assenza di qualunque
attacco.

**Soluzione:** `rot.FullPCRSelection()` restituisce l'elenco completo
degli indici PCR effettivamente quotati (`tpmtoolsclient.FullPcrSel(tpm2.AlgSHA256).PCRs`).
`main.go` lo usa sia per leggere il Golden Measurement in fase di
onboarding sia come parametro (oggi "informativo") passato a
`GetTPMQuote` — allineando esattamente cosa viene misurato a cosa il TPM
firma davvero.

## `attest.MachineState` non espone una mappa PCR grezza

**Sintomo:**
```
verifier\verifier.go:203:29: machineState.GetPcrs undefined
    (type *"...attest".MachineState has no field or method GetPcrs)
```

**Causa:** la prima versione di `verifier.go` tentava di leggere i valori
PCR "puri" dal `MachineState` restituito da `server.VerifyAttestation`.
Quel messaggio Protobuf, però, è pensato per **stati interpretati ad alto
livello** (stato GRUB, EFI, container-optimized OS su GCE...) — non
espone una mappa PCR generica per un banco SHA-256 arbitrario come quello
usato in questo progetto.

**Soluzione:** `verifier.go` estrae il `PCRDigest` **direttamente dal
`TPMS_ATTEST`**, usando `legacy/tpm2.DecodeAttestationData` — la stessa
struttura standard TCG che `TPM2_Quote` produce e firma, quindi già
implicitamente autenticata dalla verifica di firma appena eseguita da
`server.VerifyAttestation` (si decodifica lo stesso blob la cui firma è
già stata validata, non un input non fidato separato). Il Golden
Measurement è tornato a essere un digest combinato unico (come nella
prima versione del prototipo), non una mappa per-PCR — più semplice e più
allineato a come viene effettivamente confrontato lato TPM.

## Nessuna notifica attiva verso l'Enforcement

**Problema (non un bug, un gap architetturale identificato per
analisi):** confrontando il codice con il sequence diagram del
protocollo, il passo "Revoca Immediata Routing" della Fase 4 non aveva
alcuna controparte nel codice — quando il Verifier bruciava una
generazione (es. per un replay attack), l'Enforcement non veniva mai
avvisato attivamente: il routing decadeva solo alla scadenza naturale del
token (fino a `DefaultTokenTTL` = 30 secondi), una finestra di
esposizione che il documento di analisi originale elenca esplicitamente
come metrica da misurare ("Detection & Quarantine Window").

**Soluzione — canale di notifica senza deadlock:**
introdotto un meccanismo di hook (`Verifier.OnRevoke`/`Verifier.Revoke` +
`Enforcement.Revoke`), con un accorgimento di concorrenza non ovvio:
`sync.Mutex` in Go non è rientrante — se gli hook venissero chiamati
mentre il Verifier detiene ancora il proprio lock interno (`v.mu`), un
hook che in futuro richiamasse un metodo del Verifier andrebbe in
deadlock (una goroutine che aspetta un lock già posseduto da se stessa).
La soluzione strutturale: `VerifyQuote` è stata scissa in un guscio
pubblico e una funzione privata `verifyQuoteLocked`, che "fa risalire"
fuori dal lock l'informazione su *cosa* è stato bruciato; gli hook
vengono chiamati solo **dopo** che il lock è stato rilasciato, mai
durante. Stesso pattern applicato a `Revoke` (revoca manuale).

## Context-binding del nonce

**Problema identificato per analisi (non un bug):** il nonce che il TPM
firma, nella prima integrazione, era "nudo" — nessuna informazione su
*per quale operazione* fosse stato richiesto. Una quote valida prodotta
in risposta a una challenge di rinnovo (`Renew`) poteva, in teoria,
essere ripresentata con successo come risposta a una challenge di un
contesto diverso (es. una futura migrazione), perché nulla nel dato
effettivamente firmato dal TPM lo impediva esplicitamente.

**Soluzione:** invece di firmare il nonce puro, l'Agent fa firmare al TPM
`model.ContextBoundNonce(tag, instanceID, generation, nonce)` — un digest
SHA-256 che lega insieme tag dell'operazione (`Boot`/`Renew`/`Migrate`),
identità dell'istanza, generazione e nonce originale. Il Verifier
ricalcola lo stesso valore prima di invocare `server.VerifyAttestation`.
Due strati di difesa indipendenti: un controllo esplicito su
`quote.Tag == expectedTag` (rifiuta rapidamente, senza nemmeno aprire
l'`AttestationBlob`), e il fatto che, anche aggirando quel controllo, il
confronto crittografico fallirebbe comunque perché il nonce vincolato
ricalcolato non corrisponderebbe a quello realmente firmato dal TPM.

## Aprire un secondo simulatore TPM mentre uno è ancora attivo si blocca indefinitamente

**Sintomo:** eseguendo `main.go` con la Fase 3 (che coinvolge un host
sorgente e un host target, ciascuno con il proprio TPM simulato) appena
aggiunta, l'esecuzione si è bloccata per **oltre due ore** — non un
errore, non un panic: il processo restava semplicemente vivo e
silenzioso, fermo esattamente su `rot.OpenSimulator()` per il secondo
simulatore (quello dell'host target), mentre quello del Setup iniziale
(istanza `vnf-instance-001`, ancora aperto tramite i suoi `defer`, che
scattano solo a fine `main()`) era ancora attivo.

**Causa:** `google/go-tpm-tools/simulator` sembra avere una limitazione
non documentata: **aprire un secondo simulatore mentre un altro è ancora
vivo nello stesso processo Go si blocca indefinitamente** — quasi
certamente per uno stato interno globale/condiviso nella libreria
(probabilmente ereditato dalla sua origine come porting di
un'implementazione C, pensata per un solo simulatore per processo, come
tipico in scenari di test dove se ne usa uno alla volta). Non è un
problema di prestazioni (la generazione di chiavi RSA in un simulatore
TPM software è comunque un'operazione pesante, ma nell'ordine dei
secondi, non delle ore) — è un vero blocco strutturale.

**Soluzione:** ristrutturazione di `main.go` (e successivamente di
`main_test.go`, che aveva lo stesso problema nei suoi test di
migrazione) in modo che **non ci sia mai più di un simulatore aperto
contemporaneamente in tutto il processo**. Ogni simulatore vive dentro
la propria funzione dedicata (`runFasi1a4`, `runMigrationSourcePhase`,
`runMigrationTargetPhase` in `main.go`; `runMigrationSourcePhaseForTest`,
`runMigrationTargetPhaseForTest` in `main_test.go`), il cui
`defer Close()` scatta al **ritorno di quella funzione** — non alla fine
dell'intero programma/test. In Go, senza l'uso di goroutine, il codice
di una funzione gira per intero fino al suo `return` prima che
l'istruzione successiva nel chiamante venga eseguita: l'ordine
sequenziale delle chiamate garantisce quindi, da solo, che i simulatori
non siano mai sovrapposti nel tempo, senza bisogno di alcun lock
esplicito tra loro. Dopo la correzione, l'intera Fase 3 (due simulatori,
due Attestation Key, quattro operazioni TPM2_Quote) si completa in meno
di un secondo.

## La collisione in `MigrationSourceBoundNonce`

**Sintomo:**
```
--- FAIL: TestMigrationSourceBoundNonceDiversoDaContextBoundNonce (0.00s)
    model_test.go:316: MigrationSourceBoundNonce e ContextBoundNonce
    devono produrre valori diversi anche a parità di tag/instanceID/
    generation/nonce (targetHost vuoto incluso)
```

**Causa:** un vero bug, scoperto esattamente dal test scritto per
escluderlo (non durante un'esecuzione manuale — la prova pratica del
valore dei test di collisione discussi in
[`04-testing.md`](04-testing.md)). La prima versione di
`MigrationSourceBoundNonce` scriveva `targetHost` **senza prefisso di
lunghezza**, in coda a tutti gli altri campi — un'eccezione rispetto
alla convenzione length-prefix usata ovunque nel progetto per l'unico
campo di lunghezza variabile a rischio ambiguità. Con `targetHost`
uguale alla stringa vuota, quella scrittura finale aggiungeva **zero
byte** al digest: l'output diventava così identico, byte per byte, a
quello di `ContextBoundNonce(ContextTagMigrate, instanceID, generation,
nonce)` — vanificando la distinzione tra "quote di Bootstrap/Renew con
tag Migrate" e "quote di migrazione del lato sorgente" proprio nel caso
limite (per quanto innocuo in pratica, dato che un `targetHost` vuoto
non dovrebbe mai comparire in un uso legittimo) più facile da trascurare
in fase di scrittura del codice.

**Soluzione:** `targetHost` viene ora **sempre** preceduto da 4 byte che
ne codificano la lunghezza, anche quando è zero. L'output di
`MigrationSourceBoundNonce` risulta così garantito più lungo — e quindi
diverso, con probabilità crittograficamente trascurabile di collisione —
di quello di `ContextBoundNonce` a parità di tutti gli altri campi,
indipendentemente dal valore di `targetHost`.
