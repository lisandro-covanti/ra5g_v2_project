# Test di resilienza e fault injection (Asse 5)

Questa cartella contiene la suite di test dell'**Asse 5** del piano di
valutazione prestazionale (vedi
[`../../docs/07-piano-performance.md`](../../docs/07-piano-performance.md)):
non prestazioni, ma **correttezza sotto stress e guasti** — l'obiettivo
dichiarato è validare empiricamente che il sistema degradi in modo
fail-closed prevedibile, come dichiarato nel modello di sicurezza
formale, anche in condizioni avverse.

## Perché non "tc netem" come originariamente ipotizzato nel piano

Il piano di valutazione menzionava l'iniezione di ritardo/perdita di
pacchetti a livello di rete. Non si applica a questo codice: Agent,
Verifier ed Enforcement vivono nello stesso processo e comunicano per
chiamata di funzione diretta — non esiste un vero livello di trasporto
di rete da poter degradare, per una scelta di design dichiarata fin
dall'inizio del progetto ("pacchetti Go puri, testabili in-process").
Questa suite adatta lo spirito dell'Asse 5 (resilienza sotto stress) agli
strumenti realmente applicabili a codice Go di questo tipo.

## Nessuna modifica al progetto esistente

Stesso principio già seguito in `test/benchmarks/`: nessun file dentro
`agent/`, `verifier/`, `enforcement/`, `rot/`, `model/` è stato
modificato. Il fault injection sfrutta il fatto che `rot.RootOfTrust` è
un'**interfaccia** — un wrapper che la soddisfa (`faultyRoot`, vedi
sotto) può sostituire il TPM reale ovunque Agent/Verifier se lo
aspettano, senza che il progetto originale debba sapere nulla di questa
suite.

## Struttura dei file

```
test/
└── resilience/
    ├── README.md                      — questo file
    ├── helpers_test.go                 — setup condiviso
    ├── fault_injection_test.go         — RootOfTrust "guasto" configurabile + 3 test
    ├── concurrency_stress_test.go      — stress test concorrenziale, pensato per -race
    └── fuzz_test.go                    — fuzzing di VerifyQuote
```

Package separato da `test/benchmarks` (`package resilience`, non
`package benchmarks`): concettualmente sono due cose diverse
(prestazioni vs. correttezza sotto stress), tenerle in package distinti
evita di mescolare `testing.B` e `testing.T`/`testing.F` nello stesso
insieme di file.

## I tre strumenti, e come eseguirli

### 1. Fault injection sul TPM (`fault_injection_test.go`)

`faultyRoot` avvolge il simulatore TPM reale (`*rot.TPM2RootOfTrust`)
tramite **embedding** — tecnica idiomatica Go: eredita automaticamente
tutti i metodi dell'oggetto reale, e sovrascrive solo `Attest` per
iniettare guasti configurabili (tasso di fallimento, ritardo
artificiale). Tre test:

- `TestAgentHandlesTotalTPMFailure` — TPM che fallisce sempre: verifica
  un errore Go pulito, non un panic.
- `TestAgentHandlesIntermittentTPMFailure` — TPM che fallisce al 50%:
  verifica che i tentativi riusciti non lascino stato corrotto.
- `TestVerifierRemainsResponsiveUnderSlowTPM` — TPM lento ma
  funzionante: verifica solo latenza maggiore, mai un rifiuto scorretto
  di evidenza altrimenti valida.

```bash
go test ./test/resilience/... -run TestAgentHandlesTotalTPMFailure -v
go test ./test/resilience/... -run TestAgentHandlesIntermittentTPMFailure -v
go test ./test/resilience/... -run TestVerifierRemainsResponsiveUnderSlowTPM -v
```

### 2. Stress concorrenziale con race detector (`concurrency_stress_test.go`)

20 goroutine, ciascuna esegue un mix di bootstrap, rinnovi, tentativi di
replay (deliberati — devono fallire) e migrazioni, tutte contro lo
stesso Verifier/Enforcement condivisi. A differenza dei benchmark
dell'Asse 2, qui l'obiettivo è la correttezza sotto concorrenza
disordinata, non la velocità.

```bash
go test ./test/resilience/... -run TestConcurrentMixedOperationsRaceDetector -race -v
```

**Il flag `-race` non è opzionale qui** — senza, il test verifica solo
l'assenza di panic/deadlock; con `-race`, il runtime Go strumenta ogni
accesso a memoria condivisa e segnala un data race genuino anche se non
si manifesta mai come un errore visibile nell'output (i data race sono
per natura non deterministici: il test potrebbe "passare" molte volte e
nascondere comunque un bug reale).

Un dettaglio di correttezza a cui abbiamo prestato attenzione scrivendo
questo test: **mai chiamare `t.Fatal`/`t.Error` da una goroutine diversa
da quella principale del test** — è un errore classico in Go che causa
comportamento indefinito. Gli errori dai worker vengono raccolti in un
canale e riportati solo alla fine, dalla goroutine principale.

#### Scoperta reale: il simulatore TPM non è sicuro per accesso concorrente

La prima versione di questo test faceva firmare le quote direttamente
dentro le goroutine concorrenti, condividendo lo stesso simulatore TPM
tra tutte — `-race` ha correttamente trovato una race genuina **dentro
il simulatore stesso** (`github.com/google/go-tpm-tools/simulator`, nel
suo buffer interno `bytes.Buffer`, non protetto per scritture
concorrenti). Non è un bug di RA5G: nessun deployment reale farebbe
condividere un simulatore TPM tra 20 istanze logiche diverse
contemporaneamente — ogni istanza ha il proprio TPM fisico/virtuale.
Era un difetto dello **scenario di test**, non del codice sotto esame.

Corretto separando nettamente due fasi: (1) pre-generazione
**sequenziale** di tutto il materiale TPM necessario (un solo accesso
al simulatore alla volta — la stessa tecnica già validata più volte in
`test/benchmarks/`); (2) fase concorrente che esercita **solo** il
Verifier (`VerifyQuote`, `ValidateMigrationSource` — puro Go, nessuna
dipendenza da TPM/cgo), l'unica cosa che questo test intende davvero
mettere sotto stress. Questo isola correttamente "concorrenza sul
Verifier" (realistica: molti TPM reali diversi interrogano lo stesso
Verifier) da "concorrenza sul TPM" (irrealistica, e comunque non sicura
nel simulatore usato).

#### Seconda scoperta: non un bug, la sicurezza che funziona come previsto

Anche dopo la correzione sopra, il test falliva ancora — in modo
perfettamente deterministico (100/100), sempre e solo sui job con
**sia** rinnovo **sia** migrazione sulla stessa istanza. Diagnosticato
con una strumentazione temporanea in `verifier.go` (un log per ciascuno
dei sette possibili motivi di rifiuto di `ValidateMigrationSource`, poi
rimossa): la causa era **"generazione già bruciata"**, in tutti e 100 i
casi.

Il test include deliberatamente un tentativo di replay (rigioca la
stessa quote di rinnovo una seconda volta, per verificare che venga
rifiutato) — quando l'istanza aveva *anche* una migrazione da validare,
il replay veniva testato **prima**, bruciando correttamente la
generazione per Permanent Revocation, e la successiva validazione della
migrazione sulla STESSA generazione (ormai bruciata, a ragion veduta)
falliva di conseguenza. **Non un bug nel Verifier — la sicurezza
funzionava esattamente come dimostrato formalmente in Tamarin.** Il
difetto era nell'ordine delle operazioni scelto da questo test: bruciare
deliberatamente una generazione e poi aspettarsi che operazioni
successive sulla stessa generazione abbiano ancora successo è una
contraddizione nella logica del test, non un'aspettativa legittima verso
il codice.

Corretto invertendo l'ordine: la validazione della migrazione avviene
sempre **prima** del test di rinnovo+replay (che resta, per costruzione,
l'ultima cosa fatta su una data istanza in questo test).

### 3. Fuzzing di VerifyQuote (`fuzz_test.go`)

Sottopone `v.VerifyQuote` a blob di attestazione arbitrari — non importa
se una data quote venga accettata o rifiutata (il rifiuto è corretto per
input non genuino), importa **solo** che il codice non vada mai in
panic. Per un componente che verifica dati potenzialmente forgiati da un
attaccante, è pratica di sicurezza consolidata.

```bash
go test ./test/resilience/... -fuzz=FuzzVerifyQuoteAttestationBlob -fuzztime=60s
```

Il motore di fuzzing di Go genera automaticamente varianti dei valori
nel corpus iniziale (alcuni blob deliberatamente malformati, definiti
nel test) e le usa per chiamare la funzione migliaia di volte al
secondo, mutando i byte in modo mirato — molto più efficace di input
casuali non guidati. Se trova un input che causa un fallimento, Go lo
salva automaticamente in `testdata/fuzz/FuzzVerifyQuoteAttestationBlob/`
per poterlo rieseguire deterministicamente in futuro.

#### Un bug trovato subito — nel setup del test, non in VerifyQuote

Il primo tentativo è andato in panic quasi immediatamente:
`slice bounds out of range [:32] with capacity 31`. Causa: un nonce di
test costruito da una stringa letterale contata a mano
(`"fuzz-nonce-32-byte-di-lunghezza"`), che risultava lunga 31 caratteri,
non 32 come il nome suggeriva — un errore banale, ma esattamente il tipo
di errore che una stringa letterale rende facile commettere. Corretto
sostituendo la costruzione con `make([]byte, 32)`, che non può mai
sbagliare la lunghezza per costruzione.

#### Risultato finale

Con la correzione, 60 secondi di fuzzing:

```
fuzz: elapsed: 1m0s, execs: 2052340 (33545/sec), new interesting: 0 (total: 4)
PASS
ok  	ra5g/test/resilience	65.279s
```

**Oltre 2 milioni di blob generati e mutati automaticamente**
(~34.000/secondo, 8 worker paralleli), **zero panic**. Il correttore
trovato al primo tentativo era nel setup del test, non nella logica del
Verifier — una volta risolto, il fuzzing genuino non ha trovato altro:
`VerifyQuote` degrada sempre in un rifiuto pulito (`false`) su input
avversario, mai in un comportamento indefinito.

## Riepilogo finale dell'Asse 5

| Test | Esito |
|---|---|
| `TestAgentHandlesTotalTPMFailure` | ✅ PASS |
| `TestAgentHandlesIntermittentTPMFailure` | ✅ PASS |
| `TestVerifierRemainsResponsiveUnderSlowTPM` | ✅ PASS |
| `TestConcurrentMixedOperationsRaceDetector` (con `-race`) | ✅ PASS |
| `FuzzVerifyQuoteAttestationBlob` | ✅ PASS (2 052 340 esecuzioni) |

Due scoperte reali emerse nel percorso, entrambe documentate sopra nel
dettaglio: il simulatore TPM di terze parti (`google/go-tpm-tools`) non
è sicuro per accesso concorrente allo stesso simulatore da più
goroutine; e — più significativo — una conferma **a runtime**, non solo
nel modello formale Tamarin, che Permanent Revocation si comporta
esattamente come dimostrato: una generazione bruciata resta bruciata
per qualunque operazione successiva provi a usarla.

## Prima esecuzione: cosa aspettarsi

Come per `test/benchmarks/`, questo codice non è stato compilato né
eseguito in questo ambiente (Go non è disponibile qui). Prima di
lanciare i test veri e propri:

```bash
go build ./test/resilience/...
go vet ./test/resilience/...
```

Mandami l'output di entrambi — è probabile che serva qualche correzione
al primo giro, come già successo più volte con il resto di questo
progetto.
