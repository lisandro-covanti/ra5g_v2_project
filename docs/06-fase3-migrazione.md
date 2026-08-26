# 06 — Fase 3: Migrazione Cooperativa

## Cosa implementa

Il flusso completo descritto dal sequence diagram del protocollo:
coordinamento a due lati (istanza uscente + istanza entrante, su TPM
fisicamente diversi), Atomic Commit, `GenerationLinkCert` firmato che lega
le due generazioni.

## API introdotte

**`model`**
- `QuotePayload.TargetHost` — nuovo campo, valorizzato solo nella quote
  dell'istanza uscente.
- `MigrationSourceBoundNonce(instanceID, oldGeneration, nonce, targetHost) []byte`
  — variante di `ContextBoundNonce` che lega anche l'host di destinazione.

**`agent`**
- `Agent.GetMigrationSourceQuote(oldGeneration, nonce, pcrSelection, targetHost) (*model.QuotePayload, error)`
  — produce Q_src, usando `MigrationSourceBoundNonce`.
- La quote dell'istanza **entrante** non richiede un nuovo metodo: si
  ottiene con il già esistente `GetTPMQuote(newGeneration, nonce,
  pcrSelection, model.ContextTagMigrate)`.

**`verifier`** — tre nuovi metodi pubblici:
- `BeginMigration(instanceID, targetHost) ([]byte, error)` — genera
  `n_mig`, richiede che l'istanza sia attualmente live.
- `ValidateMigrationSource(instanceID, quote) bool` — valida Q_src.
- `CompleteMigration(instanceID, newGeneration, dstQuote, newAKPublicKey, newGoldenPCRDigest) (*model.Token, *model.GenerationLinkCert, bool)`
  — valida Q_dst ed esegue l'Atomic Commit.

## Le due scelte di sicurezza discusse esplicitamente

Il punto di design più importante di questa fase, non ovvio dal solo
sequence diagram, riguarda **cosa succede quando una delle due quote non
è valida** — e la risposta è diversa a seconda di quale:

| Evento | Conseguenza | Perché |
|---|---|---|
| Q_src non valida | **Brucia la generazione corrente**, routing negato immediatamente (stesso canale di revoca già usato per il replay attack) | La quote proviene dall'istanza che sta ATTUALMENTE servendo traffico — un fallimento qui è un'anomalia sulla generazione live, non solo "un problema con la richiesta di migrazione" |
| Q_dst non valida | **Nessun BurnRecord**, la migrazione viene semplicemente abortita, `g_0` resta live e continua a servire traffico normalmente | Q_src era già stata validata: la sorgente ha provato sé stessa con successo. Un problema sul lato TARGET (rete instabile, TPM del nuovo host non pronto, immagine sbagliata) non deve mai penalizzare una sorgente sana |

Entrambe le proprietà sono verificate da test dedicati in
`main_test.go` (`TestMigrazioneSourceNonValidaBruciaGenerazioneCorrente`,
`TestMigrazioneTargetNonValidaNonComprometteSorgente`), con quote TPM
realmente firmate da un simulatore, non con dati fittizi.

## Perché Q_src e Q_dst usano funzioni di binding diverse

Q_src (istanza uscente) usa `MigrationSourceBoundNonce`, che include
`targetHost` nel digest firmato: l'istanza uscente sta **acconsentendo**
a una migrazione verso un host specifico, quindi quell'host fa parte di
ciò che sta attestando.

Q_dst (istanza entrante) usa `ContextBoundNonce` — la stessa funzione
generica già usata per Bootstrap/Renew, con tag `Migrate` al posto di
`Boot`/`Renew`. L'istanza entrante non sta "acconsentendo a migrare verso
un host": è già fisicamente lì. Sta solo attestando sé stessa in una
nuova generazione, esattamente come farebbe in un Bootstrap ordinario.

## Come l'atomicità è garantita nel codice

`CompleteMigration` esegue **tutte** le mutazioni di stato (aggiornamento
della registrazione con la nuova AK/Golden Measurement, sovrascrittura di
`v.live[instanceID]` con la nuova generazione, emissione del Token e del
`GenerationLinkCert`) sotto un **unico** `Lock()`/`Unlock()`. Per questo
è stato necessario rifattorizzare `IssueToken` in un guscio pubblico
(che acquisisce il lock) più una variante privata `issueTokenLocked`
(che lo assume già acquisito) — `CompleteMigration` chiama quest'ultima,
altrimenti chiamare il vecchio `IssueToken` da dentro `CompleteMigration`
(che detiene già il lock) sarebbe andato in deadlock, per lo stesso
motivo di `sync.Mutex` non rientrante già discusso a proposito degli
hook di revoca (vedi
[`03-problemi-e-soluzioni.md`](03-problemi-e-soluzioni.md#nessuna-notifica-attiva-verso-lenforcement)).

Prima di eseguire qualunque mutazione, `CompleteMigration` verifica
`isBurnedLocked(instanceID, newGeneration)` — un controllo difensivo che
garantisce che, nel caso limite in cui fallisse, nessuna scrittura
parziale sia già avvenuta: l'operazione resta "tutto o niente" anche in
quel caso.

## Cosa NON copre ancora questa implementazione

- **Provisioning dell'AK del target host**: `newAKPublicKey` viene
  passato a `CompleteMigration` direttamente dal chiamante (in
  `main.go`, ottenuto "fuori banda" dall'Agent target) — nessuna
  certificazione EK→AK, lo stesso limite già documentato in
  [`05-roadmap.md`](05-roadmap.md) per `RegisterInstance`.
- **Trasporto di rete**: come tutto il resto del progetto, il flusso
  resta in-process — Verifier, Agent sorgente e Agent target vivono
  nello stesso programma Go, comunicano per chiamata di funzione diretta,
  non via gRPC/HTTP.

## TTL sulle migrazioni pendenti

Una migrazione avviata con `BeginMigration` ma mai portata a termine
(l'host target non risponde più, l'Orchestrator si blocca, nessuno
richiama mai `CompleteMigration`) non resta più "appesa" indefinitamente:
`migrationState.ExpiresAt`, impostato a `now + DefaultMigrationTTL` (2
minuti, più permissivo di `DefaultTokenTTL` perché una migrazione
comporta passi aggiuntivi — istanziazione del pod target, produzione di
una nuova quote — rispetto a un semplice rinnovo), viene controllato
pigramente (stessa strategia già usata per la scadenza dei Token, non un
timer di background) sia da `ValidateMigrationSource` sia da
`CompleteMigration`: una migrazione scaduta viene ripulita e rifiutata,
**senza bruciare alcuna generazione** — un timeout non è di per sé un
evento sospetto, a differenza di un `TargetHost` o un digest PCR non
corrispondenti.
