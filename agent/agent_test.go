// package agent (white-box, come verifier_test.go/enforcement_test.go).
//
// La caratteristica di questo file, diversa dagli altri test creati finora:
// non usa MAI rot.OpenSimulator() né un vero TPM. Al suo posto definisce
// un "test double" — un tipo scritto SOLO per i test che implementa
// l'interfaccia rot.RootOfTrust restituendo dati fittizi immediati. È
// esattamente il beneficio pratico per cui, quando abbiamo introdotto il
// package rot, avevamo isolato ogni dipendenza TPM dietro un'interfaccia:
// agent.go dipende da RootOfTrust (un contratto astratto), non dal tipo
// concreto TPM2RootOfTrust — quindi qui possiamo sostituirlo con
// qualunque cosa rispetti lo stesso contratto, TPM vero o no.
//
// Conseguenza pratica: questi test durano MICROSECONDI, non i ~30ms che
// costa ciascun test in main_test.go per via del vero simulatore TPM —
// pur continuando a verificare rigorosamente la logica di agent.go (come
// costruisce il model.QuotePayload, come propaga gli errori del RoT).
package agent

import (
	"crypto"
	"errors"
	"testing"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"

	"ra5g/cryptoutil"
)

// fakeRootOfTrust implementa rot.RootOfTrust (il tipo concreto non è
// nominato qui: Go verifica la conformità all'interfaccia STRUTTURALMENTE,
// cioè "se hai tutti i metodi con la firma giusta, implementi
// l'interfaccia" — non serve una dichiarazione esplicita "implements",
// a differenza di Java/C++). Ogni campo qui sotto serve a controllare
// cosa il fake restituisce e a registrare come agent.go lo ha chiamato,
// così i test possono fare asserzioni su ENTRAMBI gli aspetti.
type fakeRootOfTrust struct {
	pubKey crypto.PublicKey

	// extendedPCRs registra, per indice PCR, la sequenza di eventi passati
	// a ExtendPCR — permette ai test di verificare che agent.ExtendPCR
	// deleghi correttamente al RoT, senza dover ispezionare stato TPM reale.
	extendedPCRs map[int][][]byte
	extendPCRErr error // se impostato, ExtendPCR lo restituisce sempre

	// attestResult/attestErr controllano cosa Attest restituisce; i due
	// campi "lastAttest*" registrano con QUALI argomenti agent.go ha
	// chiamato Attest, per verificare che pcrSelection/nonce vengano
	// propagati correttamente da GetTPMQuote.
	attestResult           *attestpb.Attestation
	attestErr              error
	lastAttestNonce        []byte
	lastAttestPCRSelection []int

	closeCalled bool
}

// newFakeRootOfTrust crea un fake pronto all'uso, con una vera chiave
// pubblica RSA (generata da cryptoutil, la stessa libreria usata da
// verifier/enforcement per le loro chiavi "usa e getta" nei test) al
// posto di una AK — sufficiente perché agent.go tratta PublicKey() come
// un valore opaco, non ne ispeziona il contenuto.
func newFakeRootOfTrust(t *testing.T) *fakeRootOfTrust {
	t.Helper()
	priv, err := cryptoutil.GenerateKeyPair()
	if err != nil {
		t.Fatalf("cryptoutil.GenerateKeyPair: %v", err)
	}
	return &fakeRootOfTrust{
		pubKey:       &priv.PublicKey,
		extendedPCRs: make(map[int][][]byte),
		// Un Attestation minimo ma non vuoto: basta a rendere
		// proto.Marshal (chiamato dentro agent.go) un'operazione
		// significativa da verificare nei test, senza bisogno di un vero
		// TPMS_ATTEST valido — agent.go non guarda dentro l'Attestation,
		// la serializza e basta.
		attestResult: &attestpb.Attestation{AkPub: []byte("fake-ak-pub-bytes")},
	}
}

func (f *fakeRootOfTrust) PublicKey() crypto.PublicKey { return f.pubKey }

func (f *fakeRootOfTrust) ExtendPCR(pcrIndex int, event []byte) error {
	if f.extendPCRErr != nil {
		return f.extendPCRErr
	}
	f.extendedPCRs[pcrIndex] = append(f.extendedPCRs[pcrIndex], event)
	return nil
}

func (f *fakeRootOfTrust) ReadPCRs(pcrSelection []int) (map[int][]byte, error) {
	out := make(map[int][]byte, len(pcrSelection))
	for _, idx := range pcrSelection {
		out[idx] = []byte("fake-pcr-value")
	}
	return out, nil
}

func (f *fakeRootOfTrust) Attest(pcrSelection []int, nonce []byte) (*attestpb.Attestation, error) {
	f.lastAttestPCRSelection = pcrSelection
	f.lastAttestNonce = nonce
	if f.attestErr != nil {
		return nil, f.attestErr
	}
	return f.attestResult, nil
}

func (f *fakeRootOfTrust) Close() error {
	f.closeCalled = true
	return nil
}

// TestNewAgentImpostaInstanceID verifica solo che il costruttore associ
// correttamente instanceID e RootOfTrust forniti — banale, ma è la base
// su cui si appoggiano implicitamente tutti gli altri test.
func TestNewAgentImpostaInstanceID(t *testing.T) {
	fake := newFakeRootOfTrust(t)
	a := NewAgent("vnf-test", fake)

	if a.InstanceID != "vnf-test" {
		t.Fatalf("InstanceID = %q, atteso %q", a.InstanceID, "vnf-test")
	}
}

// TestExtendPCRDelegaAlRootOfTrust verifica che agent.ExtendPCR non
// calcoli nulla da sé (a differenza della Fase 1, dove l'hash veniva
// calcolato in software): deve limitarsi a passare indice ed evento al
// RootOfTrust sottostante, così com'è.
func TestExtendPCRDelegaAlRootOfTrust(t *testing.T) {
	fake := newFakeRootOfTrust(t)
	a := NewAgent("vnf-test", fake)

	if err := a.ExtendPCR(3, []byte("evento-di-test")); err != nil {
		t.Fatalf("ExtendPCR: errore inatteso %v", err)
	}

	eventi := fake.extendedPCRs[3]
	if len(eventi) != 1 || string(eventi[0]) != "evento-di-test" {
		t.Fatalf("il RootOfTrust doveva ricevere esattamente 1 evento su PCR 3 con contenuto %q, ricevuto %v", "evento-di-test", eventi)
	}
}

// TestExtendPCRPropagaErroreDelRootOfTrust verifica che un errore
// restituito dal RootOfTrust (es. un vero TPM che rifiuta l'operazione)
// arrivi INTATTO al chiamante di agent.ExtendPCR, senza essere
// silenziato o trasformato.
func TestExtendPCRPropagaErroreDelRootOfTrust(t *testing.T) {
	fake := newFakeRootOfTrust(t)
	erroreAtteso := errors.New("TPM occupato")
	fake.extendPCRErr = erroreAtteso

	a := NewAgent("vnf-test", fake)

	if err := a.ExtendPCR(0, []byte("evento")); err != erroreAtteso {
		t.Fatalf("ExtendPCR doveva propagare l'errore del RootOfTrust invariato, ottenuto %v", err)
	}
}

// TestGetTPMQuoteCostruisceQuotePayloadCorretto è il test principale di
// questo file: verifica che GetTPMQuote (1) chiami Attest sul RootOfTrust
// con esattamente il nonce e la selezione PCR ricevuti, e (2) costruisca
// un model.QuotePayload con InstanceID/Generation/Nonce corretti e un
// AttestationBlob che, deserializzato, corrisponde esattamente
// all'Attestation restituito dal fake.
func TestGetTPMQuoteCostruisceQuotePayloadCorretto(t *testing.T) {
	fake := newFakeRootOfTrust(t)
	a := NewAgent("vnf-test", fake)

	nonce := []byte("nonce-di-test-12345")
	pcrSelection := []int{0, 1, 7}

	quote, err := a.GetTPMQuote(2, nonce, pcrSelection)
	if err != nil {
		t.Fatalf("GetTPMQuote: errore inatteso %v", err)
	}

	// --- Verifica dei campi del QuotePayload ---
	if quote.InstanceID != "vnf-test" {
		t.Errorf("QuotePayload.InstanceID = %q, atteso %q", quote.InstanceID, "vnf-test")
	}
	if quote.Generation != 2 {
		t.Errorf("QuotePayload.Generation = %d, atteso 2", quote.Generation)
	}
	if string(quote.Nonce) != string(nonce) {
		t.Errorf("QuotePayload.Nonce = %q, atteso %q", quote.Nonce, nonce)
	}
	if len(quote.AttestationBlob) == 0 {
		t.Fatal("QuotePayload.AttestationBlob non deve essere vuoto")
	}

	// --- Verifica che gli argomenti siano stati propagati ad Attest ---
	if string(fake.lastAttestNonce) != string(nonce) {
		t.Errorf("Attest è stato chiamato con nonce=%q, atteso %q", fake.lastAttestNonce, nonce)
	}
	if len(fake.lastAttestPCRSelection) != len(pcrSelection) {
		t.Errorf("Attest è stato chiamato con %d PCR selezionati, attesi %d", len(fake.lastAttestPCRSelection), len(pcrSelection))
	}

	// --- Verifica round-trip: deserializzando AttestationBlob si deve
	// ottenere ESATTAMENTE l'Attestation che il fake aveva restituito ---
	var decoded attestpb.Attestation
	if err := proto.Unmarshal(quote.AttestationBlob, &decoded); err != nil {
		t.Fatalf("AttestationBlob non è un Attestation Protobuf valido: %v", err)
	}
	if string(decoded.GetAkPub()) != string(fake.attestResult.GetAkPub()) {
		t.Errorf("AttestationBlob deserializzato ha AkPub=%q, atteso %q", decoded.GetAkPub(), fake.attestResult.GetAkPub())
	}
}

// TestGetTPMQuotePropagaErroreDiAttest verifica che un fallimento del
// RootOfTrust durante Attest (es. un vero TPM che non riesce a produrre
// la quote) interrompa GetTPMQuote restituendo l'errore, SENZA restituire
// comunque un QuotePayload parzialmente costruito.
func TestGetTPMQuotePropagaErroreDiAttest(t *testing.T) {
	fake := newFakeRootOfTrust(t)
	erroreAtteso := errors.New("TPM: quote fallita")
	fake.attestErr = erroreAtteso

	a := NewAgent("vnf-test", fake)

	quote, err := a.GetTPMQuote(0, []byte("nonce"), []int{0})
	if err != erroreAtteso {
		t.Fatalf("GetTPMQuote doveva propagare l'errore di Attest invariato, ottenuto %v", err)
	}
	if quote != nil {
		t.Fatalf("GetTPMQuote doveva restituire un QuotePayload nil in caso di errore, ottenuto %+v", quote)
	}
}
