package resilience

import (
	"testing"

	"ra5g/model"
)

// FuzzVerifyQuoteAttestationBlob sottopone v.VerifyQuote a blob di
// attestazione arbitrari e potenzialmente malformati — non ci interessa
// SE una data quote venga accettata o rifiutata (un rifiuto è il
// comportamento corretto per un input non genuino), ci interessa
// SOLTANTO che il codice non vada mai in panic. Per un componente che
// verifica dati potenzialmente forgiati da un attaccante, questo è
// esattamente il tipo di test che la pratica di sicurezza consolidata
// richiede: un parser/verificatore che va in panic su input malformato
// è, nel migliore dei casi, un Denial of Service; nel peggiore, la
// prima porta aperta verso qualcosa di più serio.
//
// Esegui con:
//
//	go test ./test/resilience/... -fuzz=FuzzVerifyQuoteAttestationBlob -fuzztime=60s
//
// Il motore di fuzzing di Go genera automaticamente varianti dei valori
// nel corpus iniziale (seed) e le usa per chiamare la funzione fuzzata
// migliaia di volte al secondo, mutando i byte in modo mirato a
// esplorare percorsi di codice nuovi — molto più efficace di input
// casuali non guidati.
func FuzzVerifyQuoteAttestationBlob(f *testing.F) {
	// Nota: l'apertura di un simulatore TPM richiede *testing.T, non
	// *testing.F — costruiamo qui direttamente Verifier/registrazione
	// senza passare da newTestRoot/newTestVerifierAndEnforcement
	// (pensati per *testing.T), usando solo ciò che serve per avere
	// un'istanza registrata contro cui fuzzare.
	v, err := newFuzzVerifier()
	if err != nil {
		f.Fatalf("setup del Verifier per il fuzzing fallito: %v", err)
	}

	const instanceID = "fuzz-instance"
	nonce := make([]byte, 32) // lunghezza garantita per costruzione, non contando caratteri a mano

	// Corpus iniziale: qualche blob ovviamente non valido, di lunghezza
	// e contenuto diversi — il motore di fuzzing parte da qui e muta.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte("non è affatto un messaggio protobuf valido"))
	f.Add(make([]byte, 256)) // blob di zeri, lunghezza plausibile

	f.Fuzz(func(t *testing.T, blob []byte) {
		quote := model.QuotePayload{
			InstanceID:      instanceID,
			Generation:      0,
			Tag:             model.ContextTagBoot,
			Nonce:           nonce,
			AttestationBlob: blob,
		}

		// Il risultato (true/false) non ci interessa: ci interessa
		// solo che la chiamata NON PANICHI. Un panic recuperato qui
		// verrebbe comunque segnalato dal motore di fuzzing come
		// fallimento, ma il recover esplicito produce un messaggio più
		// chiaro nel log del test.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("VerifyQuote è andato in panic con un blob di %d byte: %v", len(blob), r)
			}
		}()
		v.VerifyQuote(instanceID, quote, nonce, model.ContextTagBoot)
	})
}
