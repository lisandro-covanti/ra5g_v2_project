# RA5G — Remote Attestation Protocol per Network Functions 5G Core

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
ra5g_v2/
├── go.mod
├── main.go              # demo narrata end-to-end (Bootstrap, Continuous Attestation, Replay, Fail-Closed)
├── main_test.go          # test automatici equivalenti, con asserzioni esplicite
├── model/                # tipi dati condivisi (QuotePayload, Token, BurnRecord, ContextTag...)
├── cryptoutil/            # crittografia RSA generica, usata SOLO per le chiavi operative del Verifier (sk_V/pk_V)
├── rot/                  # interfaccia RootOfTrust + implementazione basata su TPM 2.0 (google/go-tpm-tools)
├── agent/                # Attestation Agent ($A$): interfaccia il RoT, produce evidenza firmata
├── verifier/              # Verifier ($V$): unica entità completamente fidata, valida le quote, emette i Token
└── enforcement/           # Enforcement Plane ($E$): applica le regole di instradamento sulla base dei Token
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
