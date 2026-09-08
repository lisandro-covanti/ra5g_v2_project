package benchmarks

import (
	"fmt"
	"sync/atomic"
	"testing"

	"ra5g/enforcement"
	"ra5g/model"
	"ra5g/verifier"
)

// benchmarkVerifyQuoteHorizontal misura il throughput AGGREGATO di
// numShards Verifier COMPLETAMENTE INDIPENDENTI (ciascuno con la
// propria chiave, il proprio stato, nessuna condivisione) sotto lo
// stesso identico budget totale di core (-cpu) usato da
// BenchmarkVerifyQuoteParallel — per isolare l'effetto dello SHARDING
// orizzontale da quello della singola architettura verticale.
//
// Ipotesi da verificare (formulata PRIMA di raccogliere i dati, non
// dopo): il profiling di BenchmarkVerifyQuoteParallel ha già escluso il
// lock v.mu come collo di bottiglia — il costo dominante è CPU-bound
// (aritmetica RSA + decodifica protobuf, ~2/3 del tempo). Se questa
// diagnosi è corretta, distribuire il carico su più Verifier
// indipendenti ma sulla STESSA macchina, con lo STESSO numero totale di
// core disponibili, NON dovrebbe aumentare il throughput aggregato: i
// cicli di CPU necessari per l'aritmetica RSA restano gli stessi,
// indipendentemente da quale oggetto Verifier "possiede" quella
// chiamata. Lo sharding rimuoverebbe un problema (contesa sul lock) che
// i dati raccolti finora indicano non essere il problema reale.
//
// Con numShards=1 questo benchmark si riduce esattamente a
// BenchmarkVerifyQuoteParallel — è la baseline diretta di confronto.
//
// REQUISITO: -benchtime=Nx esplicito, stesso motivo degli altri
// benchmark con pre-generazione.
func benchmarkVerifyQuoteHorizontal(b *testing.B, numShards int) {
	b.Helper()

	// AGGIORNAMENTO: la prima versione apriva un simulatore TPM PER
	// SHARD, tenendoli tutti attivi contemporaneamente — esattamente lo
	// stesso pattern già identificato come causa di blocco indefinito
	// in ../../docs/03-problemi-e-soluzioni.md, e già corretto una volta
	// in questa stessa suite (BenchmarkMigrationCompleteAtomic), qui
	// ripetuto per distrazione. Non serve comunque un TPM realmente
	// diverso per shard: l'ipotesi sotto esame riguarda l'indipendenza
	// dello STATO DEL VERIFIER (chiave sk_V, mappe interne, lock), non
	// quella dell'Agent/TPM — un solo simulatore, condiviso da tutti gli
	// shard, è sufficiente e corretto per questo test.
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	type shardState struct {
		v *verifier.Verifier
		e *enforcement.Enforcement
	}

	shards := make([]shardState, numShards)
	for s := 0; s < numShards; s++ {
		v, e := newBenchVerifierAndEnforcement(b)
		shards[s] = shardState{v: v, e: e}
	}

	type verifyJob struct {
		shardIdx   int
		instanceID string
		nonce      []byte
		quote      model.QuotePayload
	}

	jobs := make([]verifyJob, b.N)
	for i := 0; i < b.N; i++ {
		s := i % numShards
		instanceID := fmt.Sprintf("bench-horiz-%d-%d", s, i)
		a := bootstrapInstance(b, shards[s].v, shards[s].e, br, instanceID)

		nonce, err := shards[s].v.GenerateNonce(instanceID)
		if err != nil {
			b.Fatalf("GenerateNonce (pre-generazione, shard %d, iterazione %d): %v", s, i, err)
		}
		quote, err := a.GetTPMQuote(0, nonce, br.pcrSelection, model.ContextTagRenew)
		if err != nil {
			b.Fatalf("GetTPMQuote (pre-generazione, shard %d, iterazione %d): %v", s, i, err)
		}
		jobs[i] = verifyJob{shardIdx: s, instanceID: instanceID, nonce: nonce, quote: *quote}
	}

	var nextJob int64 = -1

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := atomic.AddInt64(&nextJob, 1)
			j := jobs[i]
			sh := shards[j.shardIdx]
			if ok := sh.v.VerifyQuote(j.instanceID, j.quote, j.nonce, model.ContextTagRenew); !ok {
				b.Fatalf("VerifyQuote fallita inaspettatamente (shard %d, job %d)", j.shardIdx, i)
			}
		}
	})
}

// BenchmarkVerifyQuoteHorizontal1 — baseline, un solo Verifier
// (equivalente a BenchmarkVerifyQuoteParallel).
func BenchmarkVerifyQuoteHorizontal1(b *testing.B) {
	benchmarkVerifyQuoteHorizontal(b, 1)
}

// BenchmarkVerifyQuoteHorizontal2 — carico distribuito su 2 Verifier
// indipendenti, sullo STESSO numero totale di core (-cpu) del test
// precedente.
func BenchmarkVerifyQuoteHorizontal2(b *testing.B) {
	benchmarkVerifyQuoteHorizontal(b, 2)
}

// BenchmarkVerifyQuoteHorizontal4 — carico distribuito su 4 Verifier
// indipendenti, stesso principio.
func BenchmarkVerifyQuoteHorizontal4(b *testing.B) {
	benchmarkVerifyQuoteHorizontal(b, 4)
}
