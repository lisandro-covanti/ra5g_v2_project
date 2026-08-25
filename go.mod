module ra5g

go 1.22

// ATTENZIONE: questi sono i moduli necessari per la Fase 2. Non essendo
// disponibile un accesso di rete al proxy dei moduli Go in questo ambiente
// di sviluppo, le direttive "require" seguenti NON sono state risolte/
// verificate automaticamente con `go mod tidy`. Alla prima apertura del
// progetto in un ambiente con rete, esegui:
//
//   go mod tidy
//
// che scaricherà le versioni correnti e popolerà go.sum di conseguenza. Le
// versioni indicate qui sono indicative: usa quelle che `go mod tidy`
// risolve, salvo incompatibilità segnalate dal compilatore.
require (
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	google.golang.org/protobuf v1.34.2
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-attestation v0.5.0 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.9.3 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
