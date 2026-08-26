# 04 — Strategia di test

## Convenzione di collocazione

Go non usa una cartella `tests/` separata: un file che termina in
`_test.go`, collocato in una cartella, appartiene allo **stesso package**
dei file `.go` accanto a lui. `go test` lo scopre automaticamente, senza
bisogno di registrarlo o importarlo da nessuna parte.

```
ra5g_v2/
├── main.go / main_test.go
├── model/            types.go / model_test.go
├── cryptoutil/         keys.go / cryptoutil_test.go
├── rot/               rot.go                          (nessun test dedicato, vedi sotto)
├── agent/             agent.go / agent_test.go
├── verifier/           verifier.go / verifier_test.go
└── enforcement/         enforcement.go / enforcement_test.go
```

## White-box vs black-box

Ogni file di test dichiara un `package` che determina cosa può vedere:

- **`package X`** (stesso nome del package testato — es. `package
  verifier` in `verifier_test.go`) — test "white-box"/"internal": può
  vedere anche i dettagli privati del package, non solo l'API esportata.
  Usato per `verifier_test.go`, `enforcement_test.go`, `agent_test.go`,
  `cryptoutil_test.go`, `model_test.go`.
- **`package X_test`** (con suffisso `_test`) — test "black-box"/
  "esterno": vede solo l'API pubblica, come la vedrebbe un vero
  consumatore del package. Usato in `main_test.go` (`package main_test`),
  perché quel file verifica lo stesso scenario end-to-end che `main.go`
  dimostra a video, non i dettagli implementativi di un singolo package.

## Cosa copre ciascun file

### `cryptoutil_test.go`
La base crittografica su cui si appoggia tutto il resto (firma/verifica
dei Token). Copre: firma→verifica riuscita; rifiuto di un messaggio
alterato anche di un solo byte; rifiuto con chiave pubblica sbagliata;
input `nil` gestiti senza panic; unicità e lunghezza dei nonce generati.
È il file più critico nonostante sia il più piccolo: un bug qui
resterebbe mascherato da tutti gli altri test, che generano sempre chiavi
"coerenti tra loro".

### `model_test.go`
Verifica la proprietà anti-collisione delle funzioni di codifica canonica
(`Token.SignedBytes`, `GenerationLinkCert.SignedBytes`,
`ContextBoundNonce`): che cambiare un solo campo di input produca sempre
un output diverso, e che la codifica sia deterministica. Un bug qui
significherebbe che una firma calcolata per un contenuto potrebbe
risultare valida anche per un contenuto diverso.

### `agent_test.go`
Usa un **test double** (`fakeRootOfTrust`, definito nello stesso file)
che implementa `rot.RootOfTrust` senza toccare alcun TPM — permette di
verificare la sola logica di `agent.go` (delega corretta a `ExtendPCR`,
propagazione degli errori, costruzione corretta del `QuotePayload`,
applicazione del context-binding del nonce) a costo di microsecondi, non
dei ~30ms che costerebbe ciascun test passando da un vero simulatore TPM.

### `verifier_test.go`
Test unitari sulla logica di business del Verifier che NON richiede un
TPM: meccanismo di notifica (`OnRevoke`/hook multipli), guardia su
`IssueToken` dopo una revoca, rifiuto di un'istanza mai registrata,
rifiuto per context tag non corrispondente (verificabile senza TPM perché
quel controllo avviene prima della deserializzazione dell'`AttestationBlob`).

### `enforcement_test.go`
Test unitari sull'Enforcement Plane, costruendo a mano Token firmati con
`cryptoutil` (senza bisogno di un Verifier completo): comportamento
Fail-Closed (token scaduto, firma non valida, istanza mai vista),
Generation Exclusivity, canale di revoca immediata (`Enforcement.Revoke`)
e la sua guardia contro notifiche riferite a generazioni ormai superate.

### `main_test.go`
L'unico livello che esercita l'intero stack **insieme**, TPM simulato
incluso: Bootstrap, Continuous Attestation, Replay Attack con verifica
esplicita che il routing si chiuda immediatamente (non al TTL),
Fail-Closed, e un test end-to-end dedicato che dimostra il rifiuto di una
quote TPM realmente valida se usata con un context tag sbagliato. È il
più lento (decine di millisecondi per test) perché ciascun test apre un
simulatore TPM 2.0 indipendente — nessuno stato condiviso tra un test e
l'altro, per garantire che l'ordine di esecuzione non influisca sul
risultato (un requisito che `go test` assume sempre).

### `rot/rot.go` — perché non ha un file di test dedicato
È già esercitato indirettamente e in modo abbastanza completo da
`main_test.go` (che passa attraverso `OpenSimulator`,
`NewTPM2RootOfTrust`, `ExtendPCR`, `ReadPCRs`, `Attest` insieme). Test
dedicati sarebbero in parte ridondanti e comunque lenti — non c'è modo di
"fintare" il TPM per testare proprio il codice che *parla* con il TPM.
Priorità bassa, non urgente.

## Come eseguire

```bash
go test ./...              # tutta la suite, riepilogo per package
go test -v ./...            # verbose: una riga per ogni singolo test
go test ./verifier/...       # solo i test di un package
go test -run TestReplay ./... # solo i test il cui nome contiene "TestReplay"
```

Un fallimento produce un output localizzato (file, riga, messaggio):

```
--- FAIL: TestReplayAttackVieneRilevatoERoutingChiusoSubito (0.03s)
    main_test.go:87: dopo un replay rilevato, il routing deve chiudersi...
FAIL
```

## Nota sui tempi

`cryptoutil`/`model`/`agent` durano microsecondi-millisecondi.
`verifier`/`enforcement` durano qualche centinaio di millisecondi in
totale — non per lentezza del codice, ma perché ogni test che genera una
coppia di chiavi RSA 2048 bit (`cryptoutil.GenerateKeyPair`) paga un
costo reale non trascurabile. Il package radice (`ra5g`, cioè
`main_test.go`) è il più lento in assoluto perché ogni suo test apre un
vero simulatore TPM 2.0 in-process.
