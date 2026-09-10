package benchmarks

import (
	"bytes"
	"crypto"
	"testing"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmtoolsserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// extractSHA256PCRDigestForBench replica, per questa suite di
// benchmark, la stessa logica (privata) presente in verifier.go che
// estrae il PCRDigest SHA-256 direttamente dal TPMS_ATTEST. Non è
// esportata dal progetto originale, ma è sufficientemente piccola (11
// righe) e basata solo su librerie esterne pubbliche da poter essere
// duplicata qui senza modificare alcun file del progetto — stesso
// principio già applicato a combinedPCRDigest in helpers_test.go.
func extractSHA256PCRDigestForBench(attestation *attestpb.Attestation) ([]byte, bool) {
	for _, q := range attestation.GetQuotes() {
		ad, decodeErr := tpm2.DecodeAttestationData(q.GetQuote())
		if decodeErr != nil || ad.AttestedQuoteInfo == nil {
			continue
		}
		if ad.AttestedQuoteInfo.PCRSelection.Hash == tpm2.AlgSHA256 {
			return ad.AttestedQuoteInfo.PCRDigest, true
		}
	}
	return nil, false
}

// BenchmarkBaselineTPMQuoteNuda misura il costo di UNA singola
// operazione TPM (TPM2_Quote), senza ALCUNA logica applicativa attorno
// — non passa da agent.GetTPMQuote (che aggiunge il context-binding del
// nonce tramite model.ContextBoundNonce), non produce un
// model.QuotePayload, non viene mai verificata. È la baseline
// "hardware/piattaforma pura" richiesta dall'Asse 3 del piano di
// valutazione (docs/07-piano-performance.md): qualunque differenza tra
// questo numero e BenchmarkBootstrap/BenchmarkRenew (Asse 1)
// rappresenta overhead aggiunto dal PROTOCOLLO, non dal TPM (reale o
// simulato) in sé.
func BenchmarkBaselineTPMQuoteNuda(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	nonce := nonce32()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := br.root.Attest(br.pcrSelection, nonce); err != nil {
			b.Fatalf("Attest: %v", err)
		}
	}
}

// BenchmarkSingleShotAttestation misura un ciclo di attestazione
// MINIMO: produzione della quote (nonce grezzo, SENZA
// model.ContextBoundNonce) + verifica crittografica reale (la STESSA
// primitiva usata da verifier.go: tpmtoolsserver.VerifyAttestation, più
// il confronto del digest PCR col Golden Measurement) — ma senza
// NESSUNO dei meccanismi che rendono RA5G "continuo" invece che
// "puntuale": nessun controllo di tag di contesto, nessuna memoria di
// nonce già usati (anti-replay), nessun Burn Record, nessun controllo
// di monotonicità della generazione, nessuno stato del Verifier.
// Rappresenta il minimo indispensabile per un challenge-response
// verificabile una tantum.
//
// La differenza tra questo numero e BenchmarkRenew (Asse 1) isola il
// costo SPECIFICO della continuità — il numero più difendibile per
// rispondere alla domanda "quanto costa rendere l'attestazione
// continua, rispetto a una singola attestazione equivalente?".
func BenchmarkSingleShotAttestation(b *testing.B) {
	br, cleanup := newBenchRoot(b)
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce := nonce32() // nonce grezzo: nessun context-binding

		attestation, err := br.root.Attest(br.pcrSelection, nonce)
		if err != nil {
			b.Fatalf("Attest (iterazione %d): %v", i, err)
		}

		blob, err := proto.Marshal(attestation)
		if err != nil {
			b.Fatalf("proto.Marshal (iterazione %d): %v", i, err)
		}

		var decoded attestpb.Attestation
		if err := proto.Unmarshal(blob, &decoded); err != nil {
			b.Fatalf("proto.Unmarshal (iterazione %d): %v", i, err)
		}

		if _, err := tpmtoolsserver.VerifyAttestation(&decoded, tpmtoolsserver.VerifyOpts{
			Nonce:      nonce,
			TrustedAKs: []crypto.PublicKey{br.root.PublicKey()},
		}); err != nil {
			b.Fatalf("VerifyAttestation (iterazione %d): %v", i, err)
		}

		actualDigest, found := extractSHA256PCRDigestForBench(&decoded)
		if !found {
			b.Fatalf("nessun digest SHA-256 trovato nell'attestazione (iterazione %d)", i)
		}
		if !bytes.Equal(actualDigest, br.golden) {
			b.Fatalf("mismatch PCR rispetto al Golden Measurement (iterazione %d)", i)
		}
	}
}
