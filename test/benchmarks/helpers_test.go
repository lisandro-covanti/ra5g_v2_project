// Package benchmarks contiene i benchmark prestazionali del protocollo
// RA5G (Asse 1 del piano di valutazione — vedi
// ../../docs/07-piano-performance.md).
//
// Vive DELIBERATAMENTE fuori dai package del progetto originale
// (agent/verifier/enforcement/rot/model): non è stata applicata né è
// necessaria alcuna modifica a quei package per costruire questa suite
// — ogni funzione usata qui era già pubblica prima che questo file
// esistesse. Questo file contiene solo le funzioni di supporto
// condivise tra i benchmark degli altri file di questa cartella; non
// definisce da solo alcun BenchmarkXxx.
package benchmarks

import (
	"crypto/sha256"
	"testing"

	"ra5g/agent"
	"ra5g/enforcement"
	"ra5g/model"
	"ra5g/rot"
	"ra5g/verifier"
)

// combinedPCRDigest replica, in Go puro, il calcolo che il TPM esegue
// internamente per produrre PCRDigest — stessa identica logica già
// presente (privata) in main.go: duplicata qui perché questa suite vive
// in un package a sé, non perché il calcolo sia cambiato.
func combinedPCRDigest(pcrValues map[int][]byte, pcrSelection []int) []byte {
	h := sha256.New()
	for _, idx := range pcrSelection {
		h.Write(pcrValues[idx])
	}
	return h.Sum(nil)
}

// benchRoot raggruppa una connessione TPM (simulata) già aperta, la sua
// selezione PCR e il Golden Measurement corrispondente. Il costo di
// setup più oneroso di tutta la suite (apertura del simulatore,
// generazione della chiave RSA dell'Attestation Key) va SEMPRE pagato
// una sola volta fuori dal ciclo temporizzato di un benchmark, mai
// ripetuto ad ogni iterazione — è compito dell'Asse 3
// (docs/07-piano-performance.md) isolare quel costo specifico, non di
// questa suite confonderlo con il costo della logica di protocollo.
type benchRoot struct {
	root         *rot.TPM2RootOfTrust
	pcrSelection []int
	golden       []byte
}

// newBenchRoot apre un simulatore TPM, misura un boot "genuino" (stessi
// valori già usati in main.go/main_test.go, per coerenza) e calcola il
// Golden Measurement corrispondente. Restituisce anche una funzione di
// chiusura, da invocare con defer dal chiamante.
func newBenchRoot(b *testing.B) (*benchRoot, func()) {
	b.Helper()

	tpmConn, err := rot.OpenSimulator()
	if err != nil {
		b.Fatalf("rot.OpenSimulator: %v", err)
	}
	root, err := rot.NewTPM2RootOfTrust(tpmConn)
	if err != nil {
		b.Fatalf("rot.NewTPM2RootOfTrust: %v", err)
	}

	pcrSelection := rot.FullPCRSelection()

	// Un Agent temporaneo, usato solo per estendere i PCR durante il
	// setup — non è l'Agent che i benchmark useranno poi (ciascuno ne
	// crea uno proprio, con l'instanceID che gli serve).
	setupAgent := agent.NewAgent("bench-setup", root)
	if err := setupAgent.ExtendPCR(0, []byte("genuine-bootloader-v1.4")); err != nil {
		b.Fatalf("ExtendPCR(0): %v", err)
	}
	if err := setupAgent.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")); err != nil {
		b.Fatalf("ExtendPCR(1): %v", err)
	}

	pcrValues, err := root.ReadPCRs(pcrSelection)
	if err != nil {
		b.Fatalf("ReadPCRs: %v", err)
	}
	golden := combinedPCRDigest(pcrValues, pcrSelection)

	br := &benchRoot{root: root, pcrSelection: pcrSelection, golden: golden}
	cleanup := func() {
		_ = root.Close()
		_ = tpmConn.Close()
	}
	return br, cleanup
}

// newBenchVerifierAndEnforcement crea una coppia Verifier/Enforcement
// pulita, con il canale di revoca già collegato — replica esattamente
// il collegamento fatto in main.go, riportato qui perché quella
// funzione di collegamento non è (né dovrebbe essere) esportata dal
// progetto originale.
func newBenchVerifierAndEnforcement(b *testing.B) (*verifier.Verifier, *enforcement.Enforcement) {
	b.Helper()

	v, err := verifier.New()
	if err != nil {
		b.Fatalf("verifier.New: %v", err)
	}
	e := enforcement.New(v.PublicKey())
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})
	return v, e
}

// bootstrapInstance esegue una singola Fase 1 completa (Challenge ->
// Quote -> VerifyQuote -> IssueToken -> UpdateRoutingRules) per una
// nuova istanza logica, usando l'Agent/TPM già aperto in br. Restituisce
// l'Agent creato, che i benchmark successivi riusano per le fasi
// seguenti (Renew, Migrazione) sulla stessa istanza.
func bootstrapInstance(b *testing.B, v *verifier.Verifier, e *enforcement.Enforcement, br *benchRoot, instanceID string) *agent.Agent {
	b.Helper()

	a := agent.NewAgent(instanceID, br.root)
	v.RegisterInstance(instanceID, br.root.PublicKey(), br.golden)

	nonce, err := v.GenerateNonce(instanceID)
	if err != nil {
		b.Fatalf("GenerateNonce: %v", err)
	}
	quote, err := a.GetTPMQuote(0, nonce, br.pcrSelection, model.ContextTagBoot)
	if err != nil {
		b.Fatalf("GetTPMQuote (boot): %v", err)
	}
	if ok := v.VerifyQuote(instanceID, *quote, nonce, model.ContextTagBoot); !ok {
		b.Fatal("bootstrap fallito inaspettatamente durante il setup del benchmark")
	}
	token, err := v.IssueToken(instanceID, 0)
	if err != nil {
		b.Fatalf("IssueToken: %v", err)
	}
	e.UpdateRoutingRules(token)
	return a
}
