# 07 — Piano di valutazione prestazionale

Questo documento definisce il piano operativo della seconda milestone
del progetto — la validazione prestazionale del protocollo RA5G — a
seguito della prima milestone (verifica formale della sicurezza tramite
Tamarin Prover, documentata in
[`verif/tamarin/README.md`](verif/tamarin/README.md)).

Le due milestone rispondono a domande diverse e complementari: la prima
dimostra che il protocollo, **se eseguito**, rispetta le proprietà di
sicurezza dichiarate; questa seconda dimostra che il protocollo è
**eseguibile con un costo prestazionale noto, misurato e accettabile**
nel contesto applicativo dichiarato (5G Core cloud-native,
containerizzato, con migrazione cooperativa tra host).

Il piano è organizzato in cinque assi, nell'ordine in cui il documento
di analisi originale li presenta e nell'ordine di dipendenza tra loro
(gli assi 2 e 3 si appoggiano sui numeri prodotti dall'asse 1).

---

## Asse 1 — Benchmark per fase del protocollo

### Obiettivo
Sostituire le misure di latenza già presenti nella demo narrata
(`main.go`, tramite `time.Since()` su singole esecuzioni non ripetute)
con misure statisticamente significative, riproducibili e comparabili
tra loro.

### Cosa costruire
Un file `benchmark_test.go`, con una funzione `func BenchmarkX(b
*testing.B)` per ciascuna fase **isolata**:

| Benchmark | Cosa misura |
|---|---|
| `BenchmarkBootstrap` | Challenge → Quote → `VerifyQuote` → `IssueToken`, fase 1 completa |
| `BenchmarkRenew` | Stesso ciclo, fase 2 |
| `BenchmarkMigrationSourceQuote` | Solo `agent.GetMigrationSourceQuote` |
| `BenchmarkMigrationValidateSource` | Solo `v.ValidateMigrationSource` |
| `BenchmarkMigrationTargetQuote` | Solo `agent.GetTPMQuote` sull'host target |
| `BenchmarkMigrationCompleteAtomic` | Solo `v.CompleteMigration`, l'Atomic Commit |
| `BenchmarkReplayDetectionAndRevoke` | Percorso di rilevamento replay + revoca immediata |

La migrazione va **sempre** scomposta nelle sue quattro sotto-fasi,
mai misurata come un unico numero aggregato: è la scomposizione stessa
a rivelare dove si concentra il costo (quasi certamente nella
generazione delle chiavi TPM lato Agent, non nella logica del
Verifier — ma va verificato, non assunto).

### Metodologia
```
go test -bench=. -benchtime=Ns -count=10 -benchmem
```
- `-count=10`: ripetizioni multiple, non un singolo campione — serve a
  calcolare media e deviazione standard, non solo un numero puntuale.
- `-benchmem`: costo in allocazioni di memoria per operazione, utile
  anche come input per l'Asse 2.
- Ogni benchmark isola la fase tramite `b.ResetTimer()` dopo l'eventuale
  setup (es. bootstrap propedeutico a un benchmark di renewal), per non
  contaminare la misura con operazioni non pertinenti.

### Output atteso
Una tabella con media, deviazione standard e p95 per ciascuna fase,
sufficientemente stabile da poter essere citata come numero di
riferimento nel capitolo di valutazione.

---

## Asse 2 — Capacità del Verifier e punto di bottleneck

### Obiettivo
Determinare quante istanze VNF concorrenti un singolo Verifier può
sostenere prima che il throughput smetta di crescere linearmente con il
parallelismo, e da lì stimare quando il disegno a Verifier singolo
richiede una seconda istanza.

### Perché è rilevante per questo progetto in particolare
Il disegno attuale prevede **un solo Verifier, con un'unica chiave
`sk_V` e uno stato interno protetto da un singolo lock (`v.mu`)** — un
potenziale collo di bottiglia strutturale, non solo prestazionale, in
un vero 5G Core con centinaia di Network Function da attestare
continuamente.

### Cosa costruire
Un benchmark **parallelo**, non seriale:
```go
func BenchmarkVerifyQuoteParallel(b *testing.B) {
    // setup: N istanze pre-registrate, quote pre-generate
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            v.VerifyQuote(...)
        }
    })
}
```
eseguito con `-cpu=1,2,4,8,16` (o il numero di core disponibili) per
tracciare la curva throughput/parallelismo.

### Metodologia di analisi
1. Misurare il throughput (`VerifyQuote`/secondo) a parallelismo
   crescente.
2. Individuare il punto in cui la curva si appiattisce (saturazione) —
   candidato principale: contesa sul lock `v.mu`, verificabile con
   `go test -bench=. -cpuprofile=cpu.prof` seguito da `go tool pprof`
   per confermare (o escludere) che il tempo sia speso in attesa del
   lock piuttosto che in crittografia.
3. Applicare un modello di coda elementare (M/M/1, o anche solo Little's
   Law: `N = λ × W`) usando la latenza media dell'Asse 1 e il throughput
   massimo misurato, per stimare — non solo osservare — quante istanze
   VNF con un dato tasso di rinnovo (`DefaultTokenTTL`) un singolo
   Verifier sostiene in stato stazionario.

### Output atteso
Una curva throughput/parallelismo, il punto di saturazione identificato
e — se confermato dal profiling — la causa strutturale (lock contention
vs. costo crittografico intrinseco), con una stima numerica di "N
istanze massime per Verifier" derivata dal modello di coda.

---

## Asse 3 — Isolamento dell'overhead di piattaforma dall'overhead di protocollo

### Obiettivo
Rispondere in modo quantitativo alla domanda "quanto costa *questo
protocollo specifico*, al netto di quanto costerebbe comunque
qualunque schema di attestazione sullo stesso hardware?" — la domanda
che una commissione porrebbe per prima di fronte a qualunque numero di
latenza riportato senza contesto.

### Le tre misure comparabili necessarie
Tutte sullo stesso ambiente, per rendere il confronto valido:

1. **(a) Baseline TPM nuda** — tempo di una singola `TPM2_Quote`
   isolata (una chiamata diretta a `rot.Attest`, senza alcuna logica
   RA5G attorno). Rappresenta il costo del TPM (simulato o reale) di
   per sé, indipendente da qualunque scelta di design del protocollo.
2. **(b) Bootstrap/Renewal RA5G completo** — già prodotto dall'Asse 1.
3. **(c) Attestazione singola senza continuità** — una quote isolata,
   senza `ContextBoundNonce`, senza controllo di monotonicità della
   generazione, senza Burn Record: il minimo indispensabile per un
   challenge-response verificabile, senza nessuno dei meccanismi che
   rendono RA5G "continuo" invece che "puntuale". Da implementare come
   percorso di codice parallelo e deliberatamente minimale, non
   riadattando `VerifyQuote` con parametri opzionali.

### Il numero che conta davvero
La differenza **(b) − (c)** isola il costo specifico della *continuità*
(context-binding, monotonicità, revoca) rispetto al costo di una
semplice attestazione puntuale. È il numero più difendibile in sede di
tesi: *"il protocollo aggiunge X ms rispetto a un'attestazione singola
equivalente, per ottenere le garanzie di continuità descritte nella
Sezione [verifica formale]"*.

### Il confronto con l'attestazione "nuda" a livello di piattaforma
Va inoltre eseguita la stessa migrazione/rinnovo **senza** RA5G (es.
Docker/CRIU nudo, senza alcuna attestazione) per quantificare il "costo
della sicurezza" nel suo complesso rispetto a un'operazione priva di
qualunque garanzia — un secondo numero, distinto dal precedente, utile
come inquadramento generale del capitolo.

### Nota sull'ambiente Docker + NFS
Se il checkpoint/stato dell'istanza durante la migrazione (es. via
CRIU) usa NFS come storage condiviso tra host, il tempo di
trasferimento va misurato **separatamente** dal tempo di attestazione
— altrimenti diventa impossibile attribuire la latenza osservata al
protocollo di sicurezza piuttosto che all'I/O di piattaforma. Questo è
anche il punto in cui l'ambiente Docker+NFS entra concretamente nella
misurazione: non nel bootstrap/renewal (dove non interviene), ma
specificamente nella fase di migrazione.

---

## Asse 4 — Confronto con lavori di ricerca esistenti

### Obiettivo
Collocare i numeri prodotti dagli Assi 1-3 rispetto allo stato
dell'arte pubblicato in remote attestation continua, per poter
affermare (o correggere) che le prestazioni ottenute sono in linea con
sistemi comparabili.

### Perché è l'unico asse che non si costruisce col codice
Richiede una ricognizione della letteratura per individuare sistemi
sufficientemente comparabili (per meccanismo, non solo per dominio
applicativo) con numeri di prestazione pubblicati — tipicamente sistemi
di continuous/periodic attestation basati su TPM in ambito cloud-native
o telco (es. Keylime e derivati, schemi basati su IMA, altri lavori di
remote attestation per NFV/5G).

### Metodologia
1. Ricerca sistematica di paper con benchmark pubblicati su: latenza di
   attestazione periodica, overhead di verifica lato server, costo di
   migrazione/live-migration con attestazione (se esistente in
   letteratura come combinazione specifica — probabile che RA5G sia
   tra i primi a trattare esplicitamente questa combinazione, il che
   renderebbe il confronto diretto limitato ma il posizionamento
   comunque utile).
2. Costruzione di una tabella comparativa con normalizzazione esplicita
   delle condizioni sperimentali (hardware, TPM simulato vs. reale,
   dimensione della rete testata) — un confronto senza questa
   normalizzazione dichiarata è metodologicamente debole e va evitato.

### Output atteso
Una tabella comparativa e un paragrafo di posizionamento: dove RA5G si
colloca rispetto allo stato dell'arte, e quali differenze di design
spiegano eventuali scostamenti (es. il costo aggiuntivo della
migrazione cooperativa a doppio lato, assente nei sistemi di sola
attestazione periodica).

---

## Asse 5 — Test di resilienza e fault injection

### Obiettivo
Validare empiricamente che il sistema degradi in modo **fail-closed
prevedibile**, come dichiarato nel modello di sicurezza, anche in
condizioni di rete e di piattaforma avverse — non solo nelle condizioni
ideali con cui i test funzionali e i benchmark dell'Asse 1 sono
eseguiti.

### Scenari da costruire

**5.1 — Iniezione di ritardo/perdita di pacchetti**
`tc netem` sulle interfacce di rete Docker tra Agent, Verifier ed
Enforcement, con profili crescenti di latenza e perdita. Osservare se
il sistema nega l'instradamento in modo pulito (fail-closed) o produce
comportamenti non specificati (es. stati intermedi non previsti dal
modello Tamarin) sotto degrado di rete.

**5.2 — TPM artificialmente lento o non responsivo**
Introdurre un ritardo artificiale nelle risposte del TPM (simulato o
reale) per validare empiricamente il comportamento di
`DefaultMigrationTTL` sotto condizioni avverse reali — verificando in
particolare che una migrazione che supera il TTL venga effettivamente
ripulita e rifiutata, come dimostrato formalmente nel modello, anche
quando il ritardo non è quello ideale dei test in laboratorio.

**5.3 — Interruzione a metà di una sequenza multi-fase**
Terminazione forzata del processo (Agent o Verifier) in punti diversi
della sequenza di migrazione (dopo `BeginMigration`, dopo
`ValidateMigrationSource`, durante `CompleteMigration`), per verificare
che al riavvio il sistema non si trovi in uno stato ambiguo — la
controparte empirica del lemma `migration_atomicity` già dimostrato
formalmente.

### Output atteso
Per ciascuno scenario: comportamento osservato, confronto esplicito con
il comportamento *previsto* dal modello di sicurezza formale (dove
applicabile — scenario 5.3 in particolare), ed eventuali scostamenti
documentati come limiti noti dell'implementazione (distinti da limiti
del protocollo, secondo la stessa distinzione già usata nella verifica
formale tra bug di implementazione e bug di design).

---

## Prerequisiti d'ambiente

- Ambiente Docker con rete configurabile (per `tc netem`, Asse 5).
- Storage NFS condiviso tra almeno due host/container, per isolare
  l'I/O di migrazione (Asse 3).
- `pprof` abilitato nei benchmark Go (Asse 2).
- Se disponibile, un secondo ambiente con TPM hardware reale (non
  simulato) per almeno la baseline nuda dell'Asse 3 — anche una singola
  misura di confronto simulato/reale rafforzerebbe la generalizzabilità
  dei numeri, altrimenti tutti condizionati dal simulatore software.

## Criteri di accettazione — da fissare prima di raccogliere i dati

Valori indicativi, da correggere in base ai requisiti reali del
dominio applicativo dichiarato (5G, eventualmente URLLC) prima di
iniziare le misure — non dopo aver visto i risultati:

| Metrica | Soglia indicativa |
|---|---|
| Finestra di indisponibilità durante la migrazione (Asse 1+3) | da definire in base al budget di latenza del caso d'uso dichiarato |
| Overhead di continuità, (b) − (c) dell'Asse 3 | da definire come percentuale accettabile rispetto alla baseline |
| Istanze massime per Verifier prima della saturazione (Asse 2) | da confrontare con la scala tipica di un 5G Core (centinaia di NF) |
| Comportamento sotto fault injection (Asse 5) | sempre fail-closed, nessuna eccezione ammessa |

## Ordine di esecuzione consigliato

1. **Asse 1** — base numerica per tutto il resto.
2. **Asse 3** (baseline nuda e attestazione singola) — può procedere in
   parallelo con l'Asse 1, riusa in parte lo stesso codice.
3. **Asse 2** — richiede i numeri di latenza dell'Asse 1 per il modello
   di coda.
4. **Asse 5** — richiede l'ambiente Docker+NFS comunque necessario per
   completare l'Asse 3.
5. **Asse 4** — indipendente dagli altri, può essere condotto in
   qualunque momento, idealmente in parallelo fin dall'inizio.
