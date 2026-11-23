package benchmarks

import (
	"fmt"
	"testing"

	"ra5g/model"
)

// BenchmarkReplayDetectionAndRevoke misura il costo del percorso di
// rilevamento replay + revoca immediata (il ramo "nonce già consumato"
// di VerifyQuote, che comprende la generazione del BurnRecord e la
// notifica dell'hook di revoca verso Enforcement).
//
// AGGIORNAMENTO: stessa correzione già applicata a
// BenchmarkMigrationValidateSource/CompleteAtomic — la prima versione
// usava b.StopTimer()/b.StartTimer() per escludere bootstrap e primo
// utilizzo del nonce dal tempo misurato, ma -benchmem conta le
// allocazioni sull'intera esecuzione del ciclo b.N indipendentemente
// dallo stato del timer, contaminando B/op e allocs/op. Corretto
// pre-generando b.N istanze indipendenti — ciascuna già bootstrappata,
// con una quote già "consumata" una prima volta — PRIMA di avviare il
// timer. Istanze indipendenti sono necessarie perché la revoca è
// permanente per costruzione (Permanent Revocation): non avrebbe senso
// rigiocare la stessa quote due volte sulla stessa istanza già bruciata
// all'interno del ciclo cronometrato.
//
// REQUISITO: va eseguito con -benchtime=Nx esplicito, come gli altri
// due benchmark corretti allo stesso modo — vedi il commento in
// migration_benchmarks_test.go per il motivo.
func BenchmarkReplayDetectionAndRevoke(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)

	instanceIDs := make([]string, b.N)
	quotes := make([]model.QuotePayload, b.N)
	nonces := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		instanceIDs[i] = fmt.Sprintf("bench-replay-%d", i)
		a := bootstrapInstance(b, v, e, br, instanceIDs[i])

		nonce, err := v.GenerateNonce(instanceIDs[i])
		if err != nil {
			b.Fatalf("GenerateNonce (pre-generazione, istanza %d): %v", i, err)
		}
		quote, err := a.GetTPMQuote(0, nonce, br.pcrSelection, model.ContextTagRenew)
		if err != nil {
			b.Fatalf("GetTPMQuote (pre-generazione, istanza %d): %v", i, err)
		}
		if ok := v.VerifyQuote(instanceIDs[i], *quote, nonce, model.ContextTagRenew); !ok {
			b.Fatalf("primo utilizzo del nonce (pre-generazione) fallito per l'istanza %d", i)
		}
		nonces[i] = nonce
		quotes[i] = *quote
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Rigioca la STESSA quote: deve fallire, innescando il
		// percorso di rilevamento replay + revoca — è esattamente
		// questo il percorso che il benchmark misura.
		if ok := v.VerifyQuote(instanceIDs[i], quotes[i], nonces[i], model.ContextTagRenew); ok {
			b.Fatalf("il replay non è stato rilevato durante il benchmark (istanza %d)", i)
		}
	}
}
