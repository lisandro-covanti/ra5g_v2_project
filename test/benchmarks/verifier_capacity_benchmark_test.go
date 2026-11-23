package benchmarks

import (
	"fmt"
	"os"
	"runtime/pprof"
	"sync/atomic"
	"testing"

	"ra5g/model"
)

// BenchmarkVerifyQuoteParallel misura il throughput di v.VerifyQuote al
// variare del parallelismo (Asse 2 del piano di valutazione — vedi
// ../../docs/07-piano-performance.md). A differenza dei benchmark
// dell'Asse 1 (che misurano la latenza di UNA chiamata), questo misura
// quante chiamate al SECONDO il Verifier sostiene quando multiple
// goroutine lo interrogano contemporaneamente — rilevante perché il
// disegno attuale prevede un solo Verifier, con un unico lock (v.mu) a
// protezione dello stato condiviso: un potenziale collo di bottiglia
// strutturale in un 5G Core con molte Network Function da attestare
// continuamente.
//
// Stessa tecnica di pre-generazione già usata per gli altri benchmark
// "corretti" dell'Asse 1 (vedi il commento in migration_benchmarks_test.go):
// b.N istanze indipendenti, ciascuna con una quote di rinnovo già
// pronta, sono preparate PRIMA di avviare il timer — necessario qui non
// solo per allocazioni pulite, ma perché ogni nonce è utilizzabile una
// sola volta (anti-replay): non si può far chiamare la STESSA quote a
// più goroutine contemporaneamente, andrebbe in conflitto con sé stessa.
//
// REQUISITO: eseguire SEMPRE con -benchtime=Nx esplicito (mai la
// modalità automatica a durata), per lo stesso motivo già discusso per
// gli altri benchmark con pre-generazione — qui aggravato dal fatto che
// il benchmark viene rieseguito una volta per ciascun valore passato a
// -cpu, moltiplicando il costo totale di pre-generazione.
//
// USO TIPICO (vedi test/benchmarks/README.md per l'analisi completa):
//
//	go test ./test/benchmarks/... -bench=BenchmarkVerifyQuoteParallel \
//	    -benchtime=200x -cpu=1,2,4,8 -benchmem
func BenchmarkVerifyQuoteParallel(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)

	type verifyJob struct {
		instanceID string
		nonce      []byte
		quote      model.QuotePayload
	}

	jobs := make([]verifyJob, b.N)
	for i := 0; i < b.N; i++ {
		instanceID := fmt.Sprintf("bench-verify-parallel-%d", i)
		a := bootstrapInstance(b, v, e, br, instanceID)

		nonce, err := v.GenerateNonce(instanceID)
		if err != nil {
			b.Fatalf("GenerateNonce (pre-generazione, istanza %d): %v", i, err)
		}
		quote, err := a.GetTPMQuote(0, nonce, br.pcrSelection, model.ContextTagRenew)
		if err != nil {
			b.Fatalf("GetTPMQuote (pre-generazione, istanza %d): %v", i, err)
		}
		jobs[i] = verifyJob{instanceID: instanceID, nonce: nonce, quote: *quote}
	}

	// Contatore atomico condiviso: distribuisce un job DIVERSO a ciascuna
	// invocazione di pb.Next(), indipendentemente da quale goroutine la
	// esegue — garantisce che ogni nonce pre-generato venga consumato
	// esattamente una volta, anche con più goroutine in esecuzione
	// simultanea.
	var nextJob int64 = -1

	// AGGIORNAMENTO: profiling CPU delimitato PROGRAMMATICAMENTE attorno
	// alla sola sezione parallela cronometrata, non tramite il flag
	// -cpuprofile (che cattura l'intera esecuzione del processo,
	// pre-generazione inclusa — confermato empiricamente: un primo
	// tentativo con -cpuprofile mostrava il 63% del tempo in
	// runtime.cgocall, quasi certamente il simulatore TPM reale invocato
	// durante bootstrapInstance, non le chiamate parallele a
	// VerifyQuote che si intendeva isolare). Attivo solo se la variabile
	// d'ambiente RA5G_CPUPROFILE è impostata, per non generare un file
	// ad ogni esecuzione normale del benchmark.
	if path := os.Getenv("RA5G_CPUPROFILE"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			b.Fatalf("impossibile creare il file di profiling %q: %v", path, err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			b.Fatalf("pprof.StartCPUProfile: %v", err)
		}
		defer pprof.StopCPUProfile()
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := atomic.AddInt64(&nextJob, 1)
			j := jobs[i]
			if ok := v.VerifyQuote(j.instanceID, j.quote, j.nonce, model.ContextTagRenew); !ok {
				b.Fatal("VerifyQuote fallita inaspettatamente durante il benchmark parallelo")
			}
		}
	})
}
