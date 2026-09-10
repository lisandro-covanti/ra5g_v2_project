package resilience

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"ra5g/rot"
)

// faultyRoot avvolge un *rot.TPM2RootOfTrust reale, iniettando guasti
// controllati SOLO sull'operazione Attest (la più critica e la più
// realisticamente soggetta a rallentamenti/indisponibilità di un vero
// TPM hardware). Tutti gli altri metodi (ExtendPCR, PublicKey, Close,
// ReadPCRs) sono ereditati automaticamente dal tipo incorporato — è
// l'idioma standard Go per il fault injection: un wrapper che soddisfa
// la stessa interfaccia (rot.RootOfTrust) dell'oggetto reale, così
// Agent/Verifier possono usarlo senza sapere che non stanno parlando
// con un TPM genuino.
type faultyRoot struct {
	*rot.TPM2RootOfTrust

	mu          sync.Mutex
	rng         *rand.Rand
	failureRate float64       // 0.0 = mai guasto, 1.0 = sempre guasto
	delay       time.Duration // ritardo artificiale prima di OGNI Attest
}

func newFaultyRoot(real *rot.TPM2RootOfTrust, seed int64, failureRate float64, delay time.Duration) *faultyRoot {
	return &faultyRoot{
		TPM2RootOfTrust: real,
		rng:             rand.New(rand.NewSource(seed)),
		failureRate:     failureRate,
		delay:           delay,
	}
}

func (f *faultyRoot) Attest(pcrSelection []int, nonce []byte) (*attestpb.Attestation, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	f.mu.Lock()
	shouldFail := f.rng.Float64() < f.failureRate
	f.mu.Unlock()

	if shouldFail {
		return nil, fmt.Errorf("guasto simulato: TPM temporaneamente non disponibile")
	}
	return f.TPM2RootOfTrust.Attest(pcrSelection, nonce)
}

// Verifica di conformità a livello di tipo: se rot.RootOfTrust dovesse
// cambiare in un modo che *faultyRoot non soddisfa più, questo file non
// compila più — un errore immediato e chiaro, non un panic a runtime
// scoperto solo eseguendo i test.
var _ rot.RootOfTrust = (*faultyRoot)(nil)

// ----------------------------------------------------------------------

// TestAgentHandlesTotalTPMFailure verifica che, quando il TPM fallisce
// SEMPRE, l'Agent restituisca un errore Go pulito — non un panic, non
// un valore silenziosamente incompleto.
func TestAgentHandlesTotalTPMFailure(t *testing.T) {
	base, cleanup := newTestRoot(t)
	defer cleanup()

	faulty := newFaultyRoot(base.root, 1, 1.0, 0) // failureRate=1.0: fallisce sempre
	v, e := newTestVerifierAndEnforcement(t)

	_, err := bootstrapTestInstance(t, v, e, faulty, base.pcrSelection, base.golden, "fault-total")
	if err == nil {
		t.Fatal("atteso un errore quando il TPM fallisce sempre, nessun errore restituito")
	}
	t.Logf("errore ricevuto correttamente: %v", err)
}

// TestAgentHandlesIntermittentTPMFailure verifica che, con un TPM che
// fallisce in modo intermittente (50% delle volte), il sistema nel suo
// complesso continui a funzionare CORRETTAMENTE sui tentativi che
// riescono — nessuno stato corrotto lasciato dai tentativi falliti.
func TestAgentHandlesIntermittentTPMFailure(t *testing.T) {
	base, cleanup := newTestRoot(t)
	defer cleanup()

	faulty := newFaultyRoot(base.root, 2, 0.5, 0)
	v, e := newTestVerifierAndEnforcement(t)

	successes := 0
	const attempts = 30
	for i := 0; i < attempts; i++ {
		instanceID := fmt.Sprintf("fault-intermittent-%d", i)
		_, err := bootstrapTestInstance(t, v, e, faulty, base.pcrSelection, base.golden, instanceID)
		if err == nil {
			successes++
		}
	}

	t.Logf("%d/%d bootstrap riusciti con un TPM che fallisce al 50%%", successes, attempts)
	if successes == 0 {
		t.Fatal("nessun bootstrap è mai riuscito — il fault injection sembra troppo aggressivo o il retry/gestione errori è rotta")
	}
	if successes == attempts {
		t.Fatal("tutti i bootstrap sono riusciti nonostante un tasso di guasto del 50%% — il fault injection non sta avendo alcun effetto")
	}
}

// TestVerifierRemainsResponsiveUnderSlowTPM verifica che un TPM lento
// (ma funzionante) non causi comportamenti anomali nel Verifier — solo
// latenza maggiore, mai un blocco indefinito o un rifiuto scorretto di
// evidenza altrimenti valida. Usa un ritardo contenuto (50ms) per non
// allungare eccessivamente il tempo di esecuzione del test.
func TestVerifierRemainsResponsiveUnderSlowTPM(t *testing.T) {
	base, cleanup := newTestRoot(t)
	defer cleanup()

	faulty := newFaultyRoot(base.root, 3, 0.0, 50*time.Millisecond) // mai guasto, sempre lento
	v, e := newTestVerifierAndEnforcement(t)

	start := time.Now()
	_, err := bootstrapTestInstance(t, v, e, faulty, base.pcrSelection, base.golden, "fault-slow")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("bootstrap fallito inaspettatamente con un TPM lento ma funzionante: %v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("il bootstrap è completato più velocemente del ritardo iniettato (%v) — il fault injection potrebbe non essere applicato", elapsed)
	}
	t.Logf("bootstrap completato correttamente in %v (con 50ms di ritardo TPM iniettato)", elapsed)
}
