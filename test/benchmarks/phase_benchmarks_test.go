package benchmarks

import (
	"fmt"
	"testing"

	"ra5g/model"
)

// BenchmarkBootstrap misura il costo end-to-end della Fase 1
// (Challenge -> Quote -> VerifyQuote -> IssueToken -> UpdateRoutingRules)
// per una NUOVA istanza logica a ogni iterazione. Riusa lo stesso TPM
// simulato/Attestation Key per tutte le iterazioni (il costo di
// apertura/generazione chiave è pagato una sola volta, fuori dal ciclo
// temporizzato — quel costo specifico appartiene all'Asse 3 del piano
// di valutazione, non a questo benchmark), ma registra un'identità
// logica diversa a ogni iterazione: ciascuna rappresenta quindi un
// bootstrap realmente "a freddo" dal punto di vista del Verifier, non
// un secondo tentativo sulla stessa istanza già viva (che il protocollo
// tratterebbe diversamente).
func BenchmarkBootstrap(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		instanceID := fmt.Sprintf("bench-boot-%d", i)
		bootstrapInstance(b, v, e, br, instanceID)
	}
}

// BenchmarkRenew misura il costo di un singolo rinnovo (Fase 2) su
// un'istanza GIÀ bootstrappata — il caso reale della Continuous
// Attestation, dove la stessa istanza rinnova molte volte nel corso
// della sua vita operativa. Il bootstrap iniziale è escluso dal tempo
// misurato (b.ResetTimer() dopo il setup).
func BenchmarkRenew(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	v, e := newBenchVerifierAndEnforcement(b)
	const instanceID = "bench-renew"
	a := bootstrapInstance(b, v, e, br, instanceID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce, err := v.GenerateNonce(instanceID)
		if err != nil {
			b.Fatalf("GenerateNonce: %v", err)
		}
		quote, err := a.GetTPMQuote(0, nonce, br.pcrSelection, model.ContextTagRenew)
		if err != nil {
			b.Fatalf("GetTPMQuote (renew): %v", err)
		}
		if ok := v.VerifyQuote(instanceID, *quote, nonce, model.ContextTagRenew); !ok {
			b.Fatal("rinnovo fallito inaspettatamente durante il benchmark")
		}
		token, err := v.IssueToken(instanceID, 0)
		if err != nil {
			b.Fatalf("IssueToken: %v", err)
		}
		e.UpdateRoutingRules(token)
	}
}
