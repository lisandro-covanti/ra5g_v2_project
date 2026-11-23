// Package resilience contiene la suite di test di resilienza e fault
// injection (Asse 5 del piano di valutazione — vedi
// ../../docs/07-piano-performance.md).
//
// Vive DELIBERATAMENTE fuori dai package del progetto originale e
// separata da test/benchmarks (concettualmente diversa: qui si misura
// CORRETTEZZA sotto stress/guasti, non prestazioni) — nessuna modifica
// al progetto esistente è stata necessaria né applicata.
package resilience

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"ra5g/agent"
	"ra5g/enforcement"
	"ra5g/model"
	"ra5g/rot"
	"ra5g/verifier"
)

// combinedPCRDigest replica, in Go puro, il calcolo che il TPM esegue
// internamente per produrre PCRDigest — stessa logica già duplicata in
// test/benchmarks/helpers_test.go, qui necessaria di nuovo perché
// questo è un package Go separato (nessuna condivisione di funzioni non
// esportate tra package diversi, anche nello stesso modulo).
func combinedPCRDigest(pcrValues map[int][]byte, pcrSelection []int) []byte {
	h := sha256.New()
	for _, idx := range pcrSelection {
		h.Write(pcrValues[idx])
	}
	return h.Sum(nil)
}

// testRoot raggruppa una connessione TPM (simulata) già aperta, la sua
// selezione PCR e il Golden Measurement corrispondente — equivalente di
// benchRoot in test/benchmarks, adattato per testing.T invece che
// testing.B.
type testRoot struct {
	root         *rot.TPM2RootOfTrust
	pcrSelection []int
	golden       []byte
}

func newTestRoot(t *testing.T) (*testRoot, func()) {
	t.Helper()

	tpmConn, err := rot.OpenSimulator()
	if err != nil {
		t.Fatalf("rot.OpenSimulator: %v", err)
	}
	root, err := rot.NewTPM2RootOfTrust(tpmConn)
	if err != nil {
		t.Fatalf("rot.NewTPM2RootOfTrust: %v", err)
	}

	pcrSelection := rot.FullPCRSelection()

	setupAgent := agent.NewAgent("resilience-setup", root)
	if err := setupAgent.ExtendPCR(0, []byte("genuine-bootloader-v1.4")); err != nil {
		t.Fatalf("ExtendPCR(0): %v", err)
	}
	if err := setupAgent.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")); err != nil {
		t.Fatalf("ExtendPCR(1): %v", err)
	}

	pcrValues, err := root.ReadPCRs(pcrSelection)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	golden := combinedPCRDigest(pcrValues, pcrSelection)

	tr := &testRoot{root: root, pcrSelection: pcrSelection, golden: golden}
	cleanup := func() {
		_ = root.Close()
		_ = tpmConn.Close()
	}
	return tr, cleanup
}

func newTestVerifierAndEnforcement(t *testing.T) (*verifier.Verifier, *enforcement.Enforcement) {
	t.Helper()

	v, err := verifier.New()
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	e := enforcement.New(v.PublicKey())
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})
	return v, e
}

// bootstrapTestInstance esegue una Fase 1 completa per una nuova
// istanza, usando un rot.RootOfTrust qualunque (reale o "guasto" — vedi
// fault_injection_test.go): funziona con entrambi perché
// rot.RootOfTrust è un'interfaccia.
func bootstrapTestInstance(t *testing.T, v *verifier.Verifier, e *enforcement.Enforcement, root rot.RootOfTrust, pcrSelection []int, golden []byte, instanceID string) (*agent.Agent, error) {
	t.Helper()

	a := agent.NewAgent(instanceID, root)
	v.RegisterInstance(instanceID, root.PublicKey(), golden)

	nonce, err := v.GenerateNonce(instanceID)
	if err != nil {
		return nil, err
	}
	quote, err := a.GetTPMQuote(0, nonce, pcrSelection, model.ContextTagBoot)
	if err != nil {
		return a, err
	}
	if ok := v.VerifyQuote(instanceID, *quote, nonce, model.ContextTagBoot); !ok {
		return a, nil // errore applicativo (rifiuto), non un errore Go — il chiamante controlla ok separatamente se serve
	}
	token, err := v.IssueToken(instanceID, 0)
	if err != nil {
		return a, err
	}
	e.UpdateRoutingRules(token)
	return a, nil
}

// newFuzzVerifier costruisce un Verifier con una singola istanza già
// registrata (chiave/Golden Measurement generati con crypto/rand, senza
// passare da un TPM simulato — un fuzz test chiama la funzione fuzzata
// decine di migliaia di volte, e aprire un simulatore TPM per ciascuna
// non sarebbe praticabile; qui serve solo una registrazione valida
// contro cui far fallire in modo pulito i blob malformati generati dal
// motore di fuzzing, non un'attestazione TPM realmente eseguita).
// Nessuna dipendenza da *testing.T o *testing.B: utilizzabile anche dal
// setup di una funzione Fuzz (*testing.F), che non condivide
// l'interfaccia comune TB per le parti usate da newTestRoot.
func newFuzzVerifier() (*verifier.Verifier, error) {
	v, err := verifier.New()
	if err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	golden := make([]byte, 32)
	v.RegisterInstance("fuzz-instance", &priv.PublicKey, golden)
	return v, nil
}
