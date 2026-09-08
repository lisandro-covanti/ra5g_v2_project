package benchmarks

import (
	"fmt"
	"testing"

	"ra5g/agent"
	"ra5g/model"
)

// nonce32 restituisce un nonce di 32 byte fisso, riusabile in benchmark
// che non coinvolgono alcun controllo di verifica lato Verifier (dove
// quindi l'unicità del nonce non ha alcuna rilevanza per la misura).
func nonce32() []byte {
	return []byte("bench-nonce-fisso-32-byte--long!")[:32]
}

// BenchmarkMigrationSourceQuote misura il costo di
// agent.GetMigrationSourceQuote (Q_src) — un'operazione puramente lato
// Agent (firma TPM), senza alcuna dipendenza dallo stato del Verifier:
// non serve alcun setup per-iterazione oltre all'apertura del TPM,
// fatta una sola volta fuori dal ciclo temporizzato.
func BenchmarkMigrationSourceQuote(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	a := agent.NewAgent("bench-mig-src", br.root)
	nonce := nonce32()
	const targetHost = "bench-target-host"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.GetMigrationSourceQuote(0, nonce, br.pcrSelection, targetHost); err != nil {
			b.Fatalf("GetMigrationSourceQuote: %v", err)
		}
	}
}

// BenchmarkMigrationTargetQuote misura il costo di agent.GetTPMQuote
// sull'host target (tag Migrate, Q_dst) — anch'essa puramente lato
// Agent, senza dipendenza dallo stato del Verifier.
func BenchmarkMigrationTargetQuote(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	a := agent.NewAgent("bench-mig-dst", br.root)
	nonce := nonce32()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.GetTPMQuote(1, nonce, br.pcrSelection, model.ContextTagMigrate); err != nil {
			b.Fatalf("GetTPMQuote (migrate target): %v", err)
		}
	}
}

// BenchmarkMigrationValidateSource misura SOLO v.ValidateMigrationSource.
//
// AGGIORNAMENTO: la prima versione usava b.StopTimer()/b.StartTimer()
// per escludere il setup (BeginMigration + Q_src) dal tempo misurato —
// ma -benchmem conta le allocazioni sull'INTERA esecuzione del ciclo
// b.N, non solo quando il timer è attivo: il setup restava escluso dal
// tempo ma NON dalle allocazioni riportate, contaminando B/op e
// allocs/op (confermato empiricamente: valori instabili anche con il
// garbage collector disattivato, quindi non imputabili al GC).
//
// Corretto pre-generando TUTTO il necessario per le b.N iterazioni
// PRIMA di avviare il timer (b.ResetTimer() azzera sia il tempo sia il
// contatore delle allocazioni). Poiché il Verifier ammette una sola
// migrazione pendente per istanza alla volta, non è possibile
// pre-generare b.N migrazioni pendenti sulla STESSA istanza (ciascuna
// nuova BeginMigration invaliderebbe la precedente) — si usano invece
// b.N istanze logiche indipendenti, ciascuna con la propria migrazione
// pendente isolata.
//
// REQUISITO: questo benchmark va eseguito con -benchtime=Nx esplicito
// (conteggio fisso di iterazioni), mai con la modalità automatica a
// durata di Go — quest'ultima potrebbe far crescere b.N a migliaia di
// iterazioni, rendendo la fase di pre-generazione (b.N bootstrap reali)
// eccessivamente lenta.
func BenchmarkMigrationValidateSource(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)
	const targetHost = "bench-target-host"

	instanceIDs := make([]string, b.N)
	quotes := make([]model.QuotePayload, b.N)
	for i := 0; i < b.N; i++ {
		instanceIDs[i] = fmt.Sprintf("bench-validate-source-%d", i)
		a := bootstrapInstance(b, v, e, br, instanceIDs[i])

		nMig, err := v.BeginMigration(instanceIDs[i], targetHost)
		if err != nil {
			b.Fatalf("BeginMigration (pre-generazione, istanza %d): %v", i, err)
		}
		qSrc, err := a.GetMigrationSourceQuote(0, nMig, br.pcrSelection, targetHost)
		if err != nil {
			b.Fatalf("GetMigrationSourceQuote (pre-generazione, istanza %d): %v", i, err)
		}
		quotes[i] = *qSrc
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok := v.ValidateMigrationSource(instanceIDs[i], quotes[i]); !ok {
			b.Fatalf("ValidateMigrationSource fallita inaspettatamente (istanza %d)", i)
		}
	}
}

// BenchmarkMigrationCompleteAtomic misura SOLO v.CompleteMigration —
// l'Atomic Commit.
//
// AGGIORNAMENTO: stessa correzione di BenchmarkMigrationValidateSource,
// stesso motivo (contaminazione delle allocazioni tramite
// StopTimer/StartTimer). Pre-genera b.N istanze indipendenti, ciascuna
// portata fino allo stato "pronta per CompleteMigration" (bootstrap +
// BeginMigration + Q_src validata + Q_dst prodotta) PRIMA di avviare il
// timer. Non serve più alcuno scambio di ruoli tra sorgente e target
// (necessario nella versione precedente per concatenare migrazioni
// sulla STESSA istanza): ogni istanza qui esegue una sola migrazione,
// g0 -> g1, indipendente dalle altre.
func BenchmarkMigrationCompleteAtomic(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)
	const targetHost = "bench-target-host"

	instanceIDs := make([]string, b.N)
	quotes := make([]model.QuotePayload, b.N)
	for i := 0; i < b.N; i++ {
		instanceIDs[i] = fmt.Sprintf("bench-complete-migration-%d", i)
		srcAgent := bootstrapInstance(b, v, e, br, instanceIDs[i])

		nMig, err := v.BeginMigration(instanceIDs[i], targetHost)
		if err != nil {
			b.Fatalf("BeginMigration (pre-generazione, istanza %d): %v", i, err)
		}
		qSrc, err := srcAgent.GetMigrationSourceQuote(0, nMig, br.pcrSelection, targetHost)
		if err != nil {
			b.Fatalf("GetMigrationSourceQuote (pre-generazione, istanza %d): %v", i, err)
		}
		if ok := v.ValidateMigrationSource(instanceIDs[i], *qSrc); !ok {
			b.Fatalf("ValidateMigrationSource (pre-generazione) fallita per l'istanza %d", i)
		}

		dstAgent := agent.NewAgent(instanceIDs[i], br.root)
		qDst, err := dstAgent.GetTPMQuote(1, nMig, br.pcrSelection, model.ContextTagMigrate)
		if err != nil {
			b.Fatalf("GetTPMQuote (migrate target, pre-generazione, istanza %d): %v", i, err)
		}
		quotes[i] = *qDst
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := v.CompleteMigration(instanceIDs[i], 1, quotes[i], br.root.PublicKey(), br.golden); !ok {
			b.Fatalf("CompleteMigration fallita inaspettatamente (istanza %d)", i)
		}
	}
}
