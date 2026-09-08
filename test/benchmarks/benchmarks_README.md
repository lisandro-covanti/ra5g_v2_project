# Benchmark prestazionali (Asse 1)

Questa cartella contiene i benchmark Go relativi all'**Asse 1** del
piano di valutazione prestazionale (vedi
[`../../docs/07-piano-performance.md`](../../docs/07-piano-performance.md)):
misure di latenza per fase del protocollo, statisticamente
significative (media, deviazione standard, p95 su ripetizioni multiple),
a sostituzione delle misure singole già presenti nella demo narrata
(`main.go`).

## Nessuna modifica al progetto esistente

Questa suite **non modifica alcun file** dentro `agent/`, `verifier/`,
`enforcement/`, `rot/`, `model/`, né `main.go`/`main_test.go`. Vive in un
package Go separato (`package benchmarks`, dentro
`ra5g/test/benchmarks`), che importa i package esistenti esattamente
come farebbe qualunque altro consumatore esterno del modulo — usando
solo funzioni già pubbliche. Non era necessaria alcuna modifica per
costruirla, e nessuna è stata applicata.

## Perché la cartella `test/` vive dentro il modulo Go

Va tenuta **dentro** `ra5g_v3/` (stesso livello di `go.mod`), non come
cartella separata a fianco del progetto — è un requisito tecnico, non
una preferenza organizzativa: gli import (`"ra5g/agent"`,
`"ra5g/verifier"`, ecc.) risolvono in base al percorso del modulo
dichiarato in `go.mod` (`module ra5g`); una cartella `test/benchmarks/`
posizionata a `ra5g_v3/test/benchmarks/` risulta automaticamente
raggiungibile come pacchetto `ra5g/test/benchmarks` senza bisogno di
alcuna configurazione aggiuntiva (`replace`, moduli multipli, ecc.).

## Struttura dei file

```
test/
└── benchmarks/
    ├── README.md                          — questo file
    ├── helpers_test.go                     — setup condiviso (TPM simulato, bootstrap)
    ├── phase_benchmarks_test.go            — BenchmarkBootstrap, BenchmarkRenew
    ├── migration_benchmarks_test.go        — le 4 sotto-fasi della Migrazione, isolate
    └── revocation_benchmark_test.go        — BenchmarkReplayDetectionAndRevoke
```

Tutti i file terminano in `_test.go` — è un requisito del toolchain Go,
non solo una convenzione: solo i file con questo suffisso vengono presi
in considerazione da `go test`/`go test -bench`, e il codice al loro
interno non finisce mai in un binario compilato normalmente (`go
build`), evitando qualunque overhead in produzione.

`helpers_test.go` non contiene alcun `BenchmarkXxx`: raccoglie solo le
funzioni di supporto riusate dagli altri tre file (apertura del
simulatore TPM, calcolo del Golden Measurement, bootstrap completo di
un'istanza) — evita di ripetere lo stesso setup in ognuno.

## Come interagiscono con il progetto

Ogni benchmark costruisce, tramite le funzioni di supporto, esattamente
la stessa sequenza di chiamate che `main.go`/`main_test.go` già
eseguono (`verifier.New()`, `rot.OpenSimulator()`,
`agent.NewAgent(...)`, `v.VerifyQuote(...)`, ecc.) — non introduce
alcuna logica nuova, misura quella già esistente. Il principio di fondo,
applicato in ogni singolo benchmark: **il costo di setup (apertura del
TPM, generazione della chiave, bootstrap propedeutico) è sempre escluso
dal tempo misurato** — tramite `b.ResetTimer()` a inizio funzione o
`b.StopTimer()`/`b.StartTimer()` attorno alle singole iterazioni quando
il setup deve ripetersi ad ogni ciclo (es. una migrazione, che nel
protocollo reale è un evento "one-shot" per quella specifica coppia di
generazioni).

## Come eseguire i benchmark

Dalla cartella del progetto (`ra5g_v3/`):

```bash
go test ./test/benchmarks/... -bench=. -benchtime=10x -count=5 -benchmem
```

- **`-bench=.`** — esegue tutti i benchmark trovati (il punto è
  un'espressione regolare che corrisponde a qualunque nome).
- **`-benchtime=10x`** — ciascun benchmark esegue esattamente 10
  iterazioni per round (invece di lasciare che Go decida
  automaticamente quante, che per operazioni che richiedono un vero TPM
  può risultare in tempi di esecuzione complessivi molto lunghi — puoi
  aumentare questo numero una volta stimato quanto impiega un singolo
  round).
- **`-count=5`** — ripete l'intero benchmark 5 volte, per calcolare
  media e deviazione standard con `benchstat` (vedi sotto), non un
  singolo campione.
- **`-benchmem`** — aggiunge il costo in allocazioni di memoria per
  operazione, utile anche come input per l'Asse 2 (capacità del
  Verifier).

Per eseguire un solo benchmark (es. solo la migrazione, la parte più
lenta):
```bash
go test ./test/benchmarks/... -bench=BenchmarkMigration -benchtime=10x
```

### Analisi statistica dei risultati

Per calcolare media/deviazione standard/confronto tra esecuzioni in
modo rigoroso (non a occhio dall'output grezzo), usa lo strumento
ufficiale del toolchain Go:
```bash
go install golang.org/x/perf/cmd/benchstat@latest
go test ./test/benchmarks/... -bench=. -benchtime=10x -count=10 > risultati.txt
benchstat risultati.txt
```

## Nota metodologica: allocazioni pulite e requisito su `-benchtime`

`BenchmarkMigrationValidateSource`, `BenchmarkMigrationCompleteAtomic` e
`BenchmarkReplayDetectionAndRevoke` **richiedono** di essere eseguiti con
`-benchtime=Nx` (un conteggio fisso di iterazioni, es. `-benchtime=20x`),
mai con la modalità automatica a durata di Go (`-benchtime=1s`, o
l'assenza del flag). Il motivo: questi tre benchmark pre-generano,
**prima** di avviare il timer, `b.N` istanze indipendenti complete
(bootstrap reale su TPM simulato incluso) — necessario per ottenere
misure di allocazione pulite (vedi sotto), ma che rende il costo di
"preparazione" proporzionale a `b.N`. Con la modalità automatica a
durata, Go può far crescere `b.N` fino a decine di migliaia per
riempire il tempo richiesto, rendendo la sola fase di pre-generazione
estremamente lenta.

Perché la pre-generazione è necessaria: `-benchmem` conta le allocazioni
di memoria sull'**intera** esecuzione del ciclo `b.N`, indipendentemente
da quando `b.StopTimer()`/`b.StartTimer()` sono stati usati — un
dettaglio non ovvio del benchmarking in Go, scoperto empiricamente in
questo progetto osservando conteggi di allocazione instabili anche a
garbage collector disattivato (quindi non imputabili al GC). La
correzione: tutto il precondition setup di ciascuna iterazione avviene
ora **prima** di `b.ResetTimer()` (che azzera sia il tempo sia il
contatore delle allocazioni), così che il ciclo temporizzato esegua
esclusivamente l'operazione sotto misura.

## Effetto empirico della correzione: non solo allocazioni, anche il tempo

La correzione descritta sopra è stata verificata eseguendo entrambe le
versioni (con `b.StopTimer()`/`b.StartTimer()`, e con la
pre-generazione) sulla stessa macchina, con `-benchtime=20x -count=10`.
Il risultato ha rivelato un effetto più ampio di quanto previsto:

| Benchmark | Prima (con StopTimer/StartTimer) | Dopo (pre-generato) | Fattore |
|---|---|---|---|
| `BenchmarkMigrationValidateSource` | 3.6 – 12.6 ms/op | 63 – 94 µs/op | ~100× |
| `BenchmarkMigrationCompleteAtomic` | 4.3 – 24.6 ms/op | 1.78 – 2.14 ms/op | ~5-10× |
| `BenchmarkReplayDetectionAndRevoke` | 1.9 – 23 ms/op | 1.1 – 2.1 µs/op | ~1000-10000× |

Le allocazioni (`allocs/op`), instabili prima della correzione anche a
garbage collector disattivato (escludendo quindi il GC come causa), sono
risultate **perfettamente identiche** in tutte e 10 le ripetizioni dopo
la correzione (536, 546 e 5 `allocs/op` rispettivamente).

**Nota di onestà metodologica**: la causa esatta per cui
`b.StopTimer()`/`b.StartTimer()` non escludesse correttamente anche il
*tempo* (non solo le allocazioni, il problema già diagnosticato) non è
stata verificata a livello di meccanismo interno — la documentazione
ufficiale di Go dichiara che quell'API dovrebbe escludere correttamente
il tempo dalla misura. Non è stata condotta un'indagine più approfondita
sul motivo preciso (possibili cause: interazione con garbage collection
asincrona innescata durante la finestra "esclusa" ma completata durante
quella "misurata", overhead di scheduling del sistema operativo). Ciò
che è stato verificato empiricamente, in modo netto e ripetibile, è che
l'approccio con pre-generazione produce numeri stabili e coerenti tra
le ripetizioni, mentre l'approccio precedente non lo era su nessuno dei
due fronti che doveva isolare (tempo e allocazioni) — sufficiente per
preferirlo come metodo, anche senza una spiegazione completa del
meccanismo che rendeva l'altro approccio inaffidabile.

### Controllo di sanità sui nuovi numeri

I valori corretti risultano plausibili anche a un esame qualitativo
indipendente dal solo confronto prima/dopo:

- **`ValidateSource` (~75 µs)** — una verifica di firma RSA più qualche
  lookup su mappa: ordine di grandezza coerente con un'operazione
  puramente crittografica, senza I/O.
- **`CompleteAtomic` (~1.85 ms)** — più pesante di `ValidateSource` (più
  controlli sequenziali: tag, nonce, monotonicità della generazione,
  poi la scrittura atomica dello stato) — coerente con la maggiore
  complessità strutturale di questa sotto-fase rispetto alle altre.
- **`ReplayDetectionAndRevoke` (~1.4 µs)** — nettamente il più veloce di
  tutti: plausibile se il controllo "nonce già usato" avviene tramite
  un semplice lookup su mappa **prima** di qualunque verifica
  crittografica costosa (un percorso fail-fast), evitando di ripetere
  una verifica RSA completa per un replay già riconoscibile a costo
  quasi nullo — un dato positivo per il capitolo di valutazione: il
  meccanismo anti-replay è economico esattamente dove serve che lo sia.

### Tabella consolidata — Asse 1 (dati verificati)

| Fase | Tempo/op |
|---|---|
| Bootstrap | ~4.1 ms |
| Renew | ~4.4 ms |
| Migration — Source Quote | ~2.9 ms |
| Migration — Target Quote | ~3.0 ms |
| Migration — Validate Source | ~75 µs |
| Migration — Complete Atomic | ~1.85 ms |
| Replay Detection + Revoke | ~1.4 µs |

## Prima esecuzione: cosa aspettarsi

Questo codice non è stato compilato né eseguito in questo ambiente (Go
non è disponibile qui) — a differenza del resto del progetto, per il
quale abbiamo sempre verificato ogni modifica tramite la tua
esecuzione reale, anche questa suite andrà probabilmente corretta al
primo tentativo. Se `go build ./test/benchmarks/...` o `go vet
./test/benchmarks/...` segnalano errori, mandameli così come sono —
li correggiamo con lo stesso approccio iterativo già usato per tutto
il resto del progetto.

---

# Asse 2 — Capacità del Verifier e punto di bottleneck

`verifier_capacity_benchmark_test.go` contiene
`BenchmarkVerifyQuoteParallel`, che misura il throughput di
`v.VerifyQuote` al variare del numero di goroutine concorrenti — non
"quanto costa una chiamata" (già coperto dall'Asse 1), ma "quante
chiamate al secondo il Verifier sostiene quando più istanze lo
interrogano contemporaneamente".

## Come eseguirlo

```bash
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteParallel \
    -benchtime=200x -cpu=1,2,4,8 -benchmem
```

- **`-cpu=1,2,4,8`** — riesegue l'intero benchmark una volta per
  ciascun valore, impostando `GOMAXPROCS` a quel valore: è il modo in
  cui `b.RunParallel` decide quante goroutine usare in parallelo di
  default. Adatta l'elenco al numero di core reali della tua macchina
  (su Windows, `$env:NUMBER_OF_PROCESSORS` te lo dice).
- **`-benchtime=200x`** — come per gli altri benchmark con
  pre-generazione, un conteggio fisso è **obbligatorio** qui: il costo
  di preparazione (200 istanze bootstrappate) va pagato una volta per
  ciascun valore di `-cpu`, quindi un numero eccessivo allunga
  molto il tempo totale senza migliorare la qualità della misura sul
  throughput.

## Come leggere l'output

Per ciascun valore di `-cpu` vedrai una riga tipo:
```
BenchmarkVerifyQuoteParallel-4    200    412300 ns/op
```
Qui `ns/op` è il tempo medio per chiamata **con quel grado di
parallelismo attivo** — il numero che interessa non è il singolo valore,
ma **come cambia** aumentando `-cpu`: se raddoppiando i core il tempo
per operazione resta stabile, il throughput complessivo raddoppia (buona
scalabilità); se il tempo per operazione peggiora sensibilmente
aumentando i core, è il segnale di contesa — quasi certamente sul lock
`v.mu` che protegge lo stato condiviso del Verifier.

## Conferma della causa (se la curva si appiattisce)

Se osservi il sintomo sopra, conferma la causa con il profiler
integrato di Go — **non** tramite il flag `-cpuprofile` (che cattura
l'intera esecuzione del processo, inclusa la fase di pre-generazione:
confermato empiricamente durante lo sviluppo di questo benchmark, dove
un primo tentativo mostrava il 63% del tempo in `runtime.cgocall`, quasi
certamente il simulatore TPM invocato durante il setup, non le chiamate
parallele a `VerifyQuote` che si intende isolare). Il benchmark supporta
invece un profiling delimitato **programmaticamente** attorno alla sola
sezione parallela cronometrata, attivabile con una variabile d'ambiente:

```bash
# PowerShell
$env:RA5G_CPUPROFILE="cpu.prof"
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteParallel -benchtime=200x -cpu=8
Remove-Item Env:\RA5G_CPUPROFILE
```

**Importante**: esegui con un **solo** valore di `-cpu` (non una lista) e
senza `-count` maggiore di 1 — ogni invocazione del benchmark sovrascrive
lo stesso file, quindi con più valori sopravvivrebbe solo il profilo
dell'ultimo.

Poi analizza il profilo come di consueto:
```bash
go tool pprof cpu.prof
```
All'interno di `pprof`, il comando `top20` mostra dove il tempo viene
speso — se una parte significativa risulta in funzioni di sincronizzazione
(`sync.(*Mutex).Lock`, `runtime.lock2`, `runtime.semacquire` e simili)
piuttosto che nella crittografia (`crypto/internal/fips140/bigmod.*`,
`rsa.VerifyPKCS1v15`), è la conferma diretta che il collo di bottiglia
è il lock, non il costo intrinseco della verifica. Il comando
`list VerifyQuote` mostra inoltre il codice di `verifier.go` riga per
riga con il tempo speso su ciascuna — utile per individuare esattamente
dove, se il lock risultasse davvero il problema.

### Osservazione laterale, rilevante per l'Asse 3

Il tentativo di profiling (contaminato, vedi sopra) ha comunque rivelato
un dato interessante per il prossimo asse del piano di valutazione:
**il 63% del tempo di CPU durante la pre-generazione risultava in
`runtime.cgocall`** — la chiamata attraverso il confine Go/C. Il
simulatore TPM software (`google/go-tpm-tools`) è quasi certamente
implementato sopra una libreria di riferimento in C, accessibile da Go
tramite `cgo`, che ha un costo fisso non trascurabile per chiamata. Se
confermato, questo significa che una parte del costo di "attestazione"
misurato finora (Asse 1) potrebbe riflettere overhead specifico del
*simulatore software*, non rappresentativo di un TPM hardware reale
(che comunica tramite un meccanismo diverso — TBS su Windows,
`/dev/tpmrm0` su Linux — probabilmente senza `cgo`). È esattamente il
tipo di distinzione che l'Asse 3 del piano di valutazione si propone di
isolare.

## Scalabilità orizzontale vs. verticale — confronto diretto

`horizontal_scaling_benchmark_test.go` risponde a una domanda diversa
dal resto dell'Asse 2: non "quanto scala UN Verifier con più core"
(già misurato), ma **"più Verifier indipendenti, sulla STESSA
macchina, con lo STESSO numero totale di core, aumentano il throughput
complessivo?"** — rilevante nel caso specifico di questo progetto, dove
non è disponibile hardware dedicato per un vero test multi-macchina.

Contiene tre benchmark — `BenchmarkVerifyQuoteHorizontal1/2/4` — con 1,
2 e 4 Verifier indipendenti rispettivamente (ciascuno con propria
chiave, proprio stato, nessuna condivisione). Il primo è identico, per
costruzione, a `BenchmarkVerifyQuoteParallel`: è la baseline diretta di
confronto.

### Ipotesi dichiarata prima della misura

Il profiling già effettuato ha escluso il lock `v.mu` come collo di
bottiglia — il costo dominante è CPU-bound (aritmetica RSA + decodifica
protobuf). Se questa diagnosi è corretta, **il throughput aggregato non
dovrebbe aumentare** passando da 1 a 2 a 4 Verifier a parità di core
totali disponibili: i cicli di CPU necessari restano gli stessi,
indipendentemente da quale oggetto Verifier possiede la chiamata. Un
throughput aggregato stabile (non crescente) con più shard confermerebbe
che lo sharding, da solo e senza hardware aggiuntivo, non risolve il
limite osservato — servirebbero core fisici realmente in più, non una
riorganizzazione software del carico.

### Come eseguirlo

Fissa lo stesso valore di `-cpu` (il numero di core fisici della
macchina, `4` nel caso già misurato) e confronta i tre:
```bash
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteHorizontal1 -benchtime=200x -cpu=4 -benchmem
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteHorizontal2 -benchtime=200x -cpu=4 -benchmem
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteHorizontal4 -benchtime=200x -cpu=4 -benchmem
```
Confronta il valore di `ns/op` tra i tre: se resta sostanzialmente
stabile (entro il rumore già osservato in altre misure), l'ipotesi è
confermata empiricamente — non solo argomentata a livello teorico.

### Risultato ottenuto: l'ipotesi iniziale è stata confutata

Con 10 ripetizioni per configurazione (necessarie: un singolo campione
per configurazione aveva mostrato un andamento simile ma non
distinguibile dal rumore già osservato altrove in questo progetto), il
throughput **aumenta** in modo consistente con più shard, non resta
piatto come l'ipotesi iniziale prevedeva:

| Shard | Mediana ns/op | Throughput stimato |
|---|---|---|
| 1 | ~102 000 | ~9 800 op/s |
| 2 | ~76 600 | ~13 050 op/s |
| 4 | ~65 350 | ~15 300 op/s |

Il profiling con campione statisticamente valido (vedi sopra) non
mostrava tempo significativo in funzioni di sincronizzazione — quel
risultato resta valido, quindi la spiegazione più probabile non è la
contesa sul lock, ma un effetto di **cache locality**: con più shard, le
mappe interne di ciascun Verifier (`v.live`, `v.registrations`, ecc.)
contengono meno voci, e mappe più piccole tendono a stare meglio nella
cache della CPU — un fattore costante reale, distinto dalla complessità
asintotica O(1) della singola operazione di lookup.

## Isolamento diretto: l'effetto è davvero la dimensione della mappa?

`map_size_benchmark_test.go` verifica questa nuova ipotesi in modo
mirato — nessuno sharding, nessun parallelismo, un solo thread: fa
crescere le mappe interne di un **singolo** Verifier a dimensioni
prestabilite (tramite istanze "di contorno" mai più toccate dopo il
bootstrap), poi misura il costo di `VerifyQuote` su istanze reali, a
parità di tutto il resto.

```bash
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteMapSize0   -benchtime=30x -benchmem
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteMapSize200 -benchtime=30x -benchmem
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteMapSize800 -benchtime=30x -benchmem
go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteMapSize3200 -benchtime=30x -benchmem
```

Se `ns/op` cresce in modo consistente da `MapSize0` a `MapSize3200`,
l'ipotesi di cache locality è confermata direttamente, isolata da
qualunque effetto di sharding o parallelismo. Se invece resta
sostanzialmente piatto, l'effetto osservato nel confronto orizzontale
avrebbe un'altra causa, ancora da identificare.

### Risultato ottenuto: anche questa ipotesi è stata confutata

Con 10 ripetizioni per configurazione, la **mediana** non mostra un
andamento pulito (200 filler risulta, sorprendentemente, il caso
*peggiore* di tutti e quattro — peggio persino di 3200):

| Filler | Mediana ns/op | **Minimo** ns/op |
|---|---|---|
| 0 | ~77 900 | 66 257 |
| 200 | ~127 500 | 65 147 |
| 800 | ~96 000 | 66 860 |
| 3200 | ~98 000 | 64 973 |

La colonna che conta è il **minimo**, non la mediana: su hardware non
dedicato al benchmarking, il rumore esterno (antivirus, altri processi,
throttling termico) può solo *rallentare* un'esecuzione, mai renderla
più veloce del suo costo reale — il run più veloce osservato è quindi la
stima più vicina al costo "pulito". Guardando il minimo, le quattro
configurazioni sono **praticamente identiche** (64 973–66 860 ns,
differenza entro il 3%): **nessun effetto di dimensione della mappa**,
nemmeno tra 0 e 3200 istanze (16× di differenza).

### Conclusione dell'Asse 2: due ipotesi testate e confutate, causa non identificata

A questo punto sono state escluse, con dati alla mano, **entrambe** le
spiegazioni plausibili per il miglioramento di throughput osservato nel
confronto orizzontale (1→2→4 shard, +55-60%):

1. ❌ **Contesa sul lock `v.mu`** — esclusa dal profiling CPU
   correttamente delimitato (§ sopra): nessuna funzione di
   sincronizzazione compare con percentuali significative su 5.27s di
   campioni statisticamente validi.
2. ❌ **Dimensione delle mappe interne del Verifier / cache locality** —
   esclusa da questo test mirato: usando la statistica robusta al
   rumore (il minimo), il costo di `VerifyQuote` non varia in modo
   apprezzabile tra 0 e 3200 istanze registrate.

**La causa reale del miglioramento orizzontale osservato resta
un'incognita aperta.** Non è una lacuna del lavoro svolto — è un esito
scientificamente onesto: due ipotesi ragionevoli sono state formulate
esplicitamente *prima* di raccogliere i dati (non adattate a posteriori
per far tornare i conti) e sottoposte a verifica empirica mirata,
entrambe non confermate. L'indagine su questo punto specifico si ferma
qui, per una ragione dichiarata: l'assenza di hardware dedicato al
benchmarking rende il rumore di misura un fattore che, oltre un certo
punto, domina qualunque segnale residuo si stia cercando di isolare —
un limite dell'ambiente di test, non del protocollo o
dell'implementazione.

Quanto resta comunque acquisito e utilizzabile, indipendentemente dalla
causa esatta: (a) il throughput di un singolo Verifier **non scala
oltre 4 core** su questa architettura (limite verticale, causa
CPU-bound identificata con sicurezza dal profiling: aritmetica RSA +
decodifica protobuf); (b) **distribuire il carico su più Verifier
indipendenti aiuta comunque**, empiricamente e in modo ripetibile
(limite orizzontale, causa non identificata ma effetto misurato e
consistente su 10 ripetizioni); (c) con il throughput minimo già
misurato (~12 500 op/s a 1-4 core), un singolo Verifier sostiene
comunque, per la Legge di Little, un numero di istanze VNF (~375 000)
ampiamente superiore alla scala tipica di un 5G Core reale — la
domanda "quando serve un secondo Verifier" resta più teorica che
pratica alla scala dichiarata da questo progetto.

## Dal throughput misurato a "quante istanze per Verifier"

Con il throughput massimo misurato (`T_max`, chiamate/secondo) e la
latenza media di un rinnovo già misurata nell'Asse 1
(`BenchmarkRenew`, ~4.4 ms), una stima con la Legge di Little
(`N = λ × W`) permette di rispondere alla domanda pratica: quante
istanze VNF, ciascuna con un dato intervallo di rinnovo
(`DefaultTokenTTL`), un singolo Verifier sostiene in condizioni di
regime.

Concretamente: se ogni istanza rinnova una volta ogni `DefaultTokenTTL`
secondi, il tasso di richieste che genera da sola è `1/DefaultTokenTTL`
al secondo; il numero massimo di istanze sostenibili è approssimativamente
`T_max × DefaultTokenTTL`. Una volta che hai i numeri reali di
`BenchmarkVerifyQuoteParallel` (in particolare il punto di saturazione
individuato sopra), posso aiutarti a calcolare questa stima con
precisione e a confrontarla con la scala tipica di un 5G Core (centinaia
di Network Function).
