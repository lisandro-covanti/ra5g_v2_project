# 5G-CRA: Continuous Remote Attestation for 5G Core VNFs

Go prototype of the remote attestation protocol presented in the Master's thesis
*"<titolo della tesi>"* (University of Padua, MSc in Cybersecurity, 2025-2026).
The version discussed in the thesis is tagged `v1.0-thesis`.

Quick start (Go 1.22+, no physical TPM required, a software simulator is used):

    go mod tidy
    go test ./...    # full test suite
    go run .         # end-to-end demo (bootstrap, continuous attestation, migration)

Formal models (Tamarin) are in `docs/verif/tamarin/`, benchmarks and resilience
tests in `test/`. Detailed documentation in `docs/` is written in Italian.

Licensed under the Apache License 2.0, see `LICENSE`.

---

Prototipo Go di un protocollo di **Remote Attestation (RA) continua ed elastica**
per Network Functions virtualizzate/containerizzate (VNF/CNF) in ambienti
cloud-native 5G Core, basato su un Hardware Root of Trust (TPM 2.0).

Il sistema garantisce che il traffico di rete venga instradato verso
un'istanza VNF/CNF **solo se** quest'ultima si trova in uno stato software
verificato crittograficamente — con verifica iniziale (Bootstrap), rinnovo
periodico (Continuous Attestation), e revoca immediata in caso di anomalia.

Questo documento è il punto di ingresso. La documentazione approfondita
vive in [`docs/`](docs/):

| Documento | Contenuto |
|---|---|
| [`docs/01-architettura.md`](docs/01-architettura.md) | Le 5 entità del protocollo, i package Go, il modello dati, chi si fida di chi |
| [`docs/02-flusso-di-esecuzione.md`](docs/02-flusso-di-esecuzione.md) | Cosa succede, passo per passo, in ciascuna fase (Bootstrap, Continuous Attestation, Replay Attack, Fail-Closed) |
| [`docs/03-problemi-e-soluzioni.md`](docs/03-problemi-e-soluzioni.md) | Log cronologico dei problemi reali incontrati integrando una vera libreria TPM, e come sono stati risolti |
| [`docs/04-testing.md`](docs/04-testing.md) | Strategia di test, cosa copre ciascun file `_test.go`, come eseguirli |
| [`docs/05-roadmap.md`](docs/05-roadmap.md) | Stato del progetto, limiti noti non ancora risolti |
| [`docs/06-fase3-migrazione.md`](docs/06-fase3-migrazione.md) | La Migrazione Cooperativa: API introdotte, le due scelte di sicurezza (Q_src vs Q_dst), come è garantita l'atomicità |
| [`docs/verif/tamarin/README.md`](docs/verif/tamarin/README.md) | Verifica formale con Tamarin Prover (cartella dedicata a sé, separata dal resto di `docs/`): cosa dimostra, mappatura codice↔modello, e — importante — quanto ci si può fidare di un modello formale |
| [`docs/07-piano-performance.md`](docs/07-piano-performance.md) | Piano operativo della validazione prestazionale (seconda milestone): benchmark per fase, capacità del Verifier, isolamento overhead di protocollo/piattaforma, confronto con lo stato dell'arte, test di resilienza |
| [`test/benchmarks/benchmarks_README.md`](test/benchmarks/benchmarks_README.md) | Risultati degli Assi 1-3: benchmark per fase, capacità/scalabilità del Verifier, isolamento overhead protocollo/piattaforma |
| [`test/resilience/resilience_README.md`](test/resilience/resilience_README.md) | Risultati dell'Asse 5: fault injection sul TPM, stress concorrenziale con race detector, fuzzing di `VerifyQuote` |

## Avvio rapido

Prerequisiti: Go 1.22+, accesso di rete per risolvere le dipendenze la
prima volta (non serve un TPM fisico: il progetto usa di default un
simulatore software).

```bash
go mod tidy      # risolve google/go-tpm, google/go-tpm-tools, protobuf
go test ./...    # esegue l'intera suite di test (vedi docs/04-testing.md)
go run .         # esegue la demo narrata end-to-end (Fase 1 + Fase 2)
```

## Struttura del progetto

```
ra5g_v2_project/
├── go.mod
├── README.md
├── main.go              # demo narrata end-to-end (Bootstrap, Continuous Attestation, Replay, Fail-Closed, Migrazione)
├── main_test.go          # test automatici equivalenti, con asserzioni esplicite
├── model/                # tipi dati condivisi (QuotePayload, Token, BurnRecord, ContextTag...)
├── cryptoutil/            # crittografia RSA generica, usata SOLO per le chiavi operative del Verifier (sk_V/pk_V)
├── rot/                  # interfaccia RootOfTrust + implementazione basata su TPM 2.0 (google/go-tpm-tools)
├── agent/                # Attestation Agent ($A$): interfaccia il RoT, produce evidenza firmata
├── verifier/              # Verifier ($V$): unica entità completamente fidata, valida le quote, emette i Token
├── enforcement/           # Enforcement Plane ($E$): applica le regole di instradamento sulla base dei Token
├── docs/                 # documentazione approfondita (vedi indice sopra)
│   └── verif/tamarin/     # verifica formale (Tamarin Prover) — vedi docs/verif/tamarin/README.md
└── test/
    ├── benchmarks/         # benchmark prestazionali (Assi 1-3) — vedi test/benchmarks/benchmarks_README.md
    └── resilience/         # test di resilienza e fault injection (Asse 5) — vedi test/resilience/resilience_README.md
```

Ogni package `.go` ha accanto il proprio `_test.go` (dove presente) — è
la convenzione standard di Go, non serve una cartella `tests/` separata
(vedi [`docs/04-testing.md`](docs/04-testing.md) per il perché).

## Stato del progetto

**Implementato e testato:** Fase 1 (Bootstrap), Fase 2 (Continuous
Attestation), Fase 3 (Migrazione Cooperativa — vedi
[`docs/06-fase3-migrazione.md`](docs/06-fase3-migrazione.md)),
rilevamento e revoca immediata di un replay attack, comportamento
Fail-Closed, context-binding del nonce (vedi
[`docs/03-problemi-e-soluzioni.md`](docs/03-problemi-e-soluzioni.md)).

**Assunzione dichiarata:** la catena EK→AK (che una Attestation Key
provenga da un TPM hardware genuino, certificata dal produttore del chip)
è considerata fidata a monte del codice, non verificata da esso —
`RegisterInstance`/`CompleteMigration` accettano la chiave pubblica
ricevuta senza validarne la provenienza hardware. Dettagli in
[`docs/05-roadmap.md`](docs/05-roadmap.md#assunzione-ekak-non-verificata-dal-codice).

**Non ancora implementato:** il livello di trasporto di rete (il
progetto resta volutamente in-process). Dettagli in
[`docs/05-roadmap.md`](docs/05-roadmap.md).
