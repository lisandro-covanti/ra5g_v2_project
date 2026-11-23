package benchmarks

import (
	"fmt"
	"testing"

	"ra5g/model"
)

// benchmarkVerifyQuoteMapSize misura il costo di v.VerifyQuote in
// funzione ESCLUSIVA del numero di istanze già registrate nello stesso
// Verifier — nessuno sharding, nessun parallelismo (un solo thread,
// stesso stile "pulito" dei benchmark dell'Asse 1) — per isolare
// direttamente l'ipotesi di cache locality emersa dal confronto
// orizzontale (vedi horizontal_scaling_benchmark_test.go): mappe
// interne più piccole potrebbero produrre lookup più veloci per
// migliore aderenza alla cache della CPU, indipendentemente da
// qualunque effetto di lock o parallelismo — che il profiling già
// effettuato (vedi README.md) ha escluso come causa dominante.
//
// numFillerInstances istanze "di contorno" vengono bootstrappate e mai
// più toccate — servono solo a far crescere le mappe interne del
// Verifier (v.live, v.registrations, ecc.) alla dimensione desiderata
// PRIMA che il ciclo cronometrato inizi. Le b.N istanze REALMENTE sotto
// misura vengono bootstrappate DOPO i filler, quindi la mappa ha già
// raggiunto la dimensione target quando le loro quote di rinnovo
// vengono preparate.
func benchmarkVerifyQuoteMapSize(b *testing.B, numFillerInstances int) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)

	for i := 0; i < numFillerInstances; i++ {
		fillerID := fmt.Sprintf("bench-filler-%d", i)
		bootstrapInstance(b, v, e, br, fillerID)
	}

	instanceIDs := make([]string, b.N)
	nonces := make([][]byte, b.N)
	quotes := make([]model.QuotePayload, b.N)
	for i := 0; i < b.N; i++ {
		instanceIDs[i] = fmt.Sprintf("bench-mapsize-target-%d", i)
		a := bootstrapInstance(b, v, e, br, instanceIDs[i])

		nonce, err := v.GenerateNonce(instanceIDs[i])
		if err != nil {
			b.Fatalf("GenerateNonce (pre-generazione, iterazione %d): %v", i, err)
		}
		quote, err := a.GetTPMQuote(0, nonce, br.pcrSelection, model.ContextTagRenew)
		if err != nil {
			b.Fatalf("GetTPMQuote (pre-generazione, iterazione %d): %v", i, err)
		}
		nonces[i] = nonce
		quotes[i] = *quote
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok := v.VerifyQuote(instanceIDs[i], quotes[i], nonces[i], model.ContextTagRenew); !ok {
			b.Fatalf("VerifyQuote fallita inaspettatamente (iterazione %d)", i)
		}
	}
}

// Le quattro dimensioni scelte (0, 200, 800, 3200) coprono lo stesso
// ordine di grandezza già usato negli altri benchmark (200 istanze,
// come in BenchmarkVerifyQuoteHorizontal1/2/4) e arrivano fino a 16
// volte tanto, per rendere un eventuale effetto di dimensione della
// mappa chiaramente visibile se presente.
//
// REQUISITO: eseguire con -benchtime=Nx esplicito e un valore
// relativamente piccolo (es. 30x-50x) — b.N si somma a
// numFillerInstances nel determinare la dimensione finale della mappa,
// quindi deve restare piccolo e COSTANTE tra le quattro varianti perché
// il confronto isoli davvero solo numFillerInstances come variabile.

func BenchmarkVerifyQuoteMapSize0(b *testing.B) {
	benchmarkVerifyQuoteMapSize(b, 0)
}

func BenchmarkVerifyQuoteMapSize200(b *testing.B) {
	benchmarkVerifyQuoteMapSize(b, 200)
}

func BenchmarkVerifyQuoteMapSize800(b *testing.B) {
	benchmarkVerifyQuoteMapSize(b, 800)
}

func BenchmarkVerifyQuoteMapSize3200(b *testing.B) {
	benchmarkVerifyQuoteMapSize(b, 3200)
}
