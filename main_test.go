// Questo file dichiara "package main_test" — NON "package main" come
// main.go. Il suffisso "_test" lo rende un package "esterno" (black-box):
// vede SOLO l'API pubblica di agent/verifier/enforcement/rot (esattamente
// ciò che vedrebbe main.go, o un vero consumatore di questi package), non
// i dettagli interni. È la scelta giusta qui perché questi test
// verificano lo stesso scenario end-to-end che main.go dimostra a video,
// non i dettagli implementativi di un singolo package (quelli sono
// coperti da verifier_test.go ed enforcement_test.go, che invece sono
// white-box).
//
// A DIFFERENZA di verifier_test.go/enforcement_test.go, questi test SONO
// più lenti (decine di millisecondi ciascuno, non microsecondi) perché
// ciascuno apre un vero simulatore TPM 2.0 in-process e ci parla
// attraverso il protocollo TPM2 standard — lo stesso costo che main.go
// paga ad ogni esecuzione, qui moltiplicato per il numero di test.
package main_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"ra5g/agent"
	"ra5g/enforcement"
	"ra5g/model"
	"ra5g/rot"
	"ra5g/verifier"
)

// combinedPCRDigest è una copia della funzione OMONIMA e privata definita
// in main.go: essendo minuscola, non è visibile da un package esterno
// come questo (package main_test), quindi va ridichiarata qui. È
// l'unica vera duplicazione in questo file — se in futuro cambia
// l'algoritmo in main.go, va allineato anche qui (un promemoria per
// quando toccheremo la logica di Golden Measurement).
func combinedPCRDigest(pcrValues map[int][]byte, pcrSelection []int) []byte {
	h := sha256.New()
	for _, idx := range pcrSelection {
		h.Write(pcrValues[idx])
	}
	return h.Sum(nil)
}

// testSystem raggruppa i quattro attori che ogni test end-to-end deve
// istanziare (Verifier, Agent, Enforcement, selezione PCR) — evita di
// dover passare quattro valori separati in giro tra le funzioni helper.
type testSystem struct {
	verifier     *verifier.Verifier
	agent        *agent.Agent
	enforcement  *enforcement.Enforcement
	pcrSelection []int
	instanceID   string
}

// setupTestSystem replica ESATTAMENTE la sezione "SETUP" di main.go:
// crea il Verifier, apre un TPM simulato, crea l'Agent, misura un boot
// "genuino", calcola e registra il Golden Measurement, crea l'Enforcement
// e collega il canale di revoca immediata. Ogni test che lo chiama
// riparte da zero con il proprio simulatore TPM indipendente — nessuno
// stato è condiviso tra un test e l'altro, quindi l'ordine di esecuzione
// dei test non ha importanza (un requisito che go test assume sempre:
// i test devono poter girare in un ordine qualsiasi, anche in parallelo).
func setupTestSystem(t *testing.T) *testSystem {
	t.Helper()

	const instanceID = "vnf-instance-test"

	v, err := verifier.New()
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	tpmConn, err := rot.OpenSimulator()
	if err != nil {
		t.Fatalf("rot.OpenSimulator: %v", err)
	}
	// t.Cleanup registra questa chiusura per essere eseguita
	// automaticamente al termine del test (successo o fallimento non
	// importa) — equivalente di un "defer", ma gestito dal framework di
	// test invece che scritto a mano in ogni singola funzione Test*.
	t.Cleanup(func() { _ = tpmConn.Close() })

	root, err := rot.NewTPM2RootOfTrust(tpmConn)
	if err != nil {
		t.Fatalf("rot.NewTPM2RootOfTrust: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	a := agent.NewAgent(instanceID, root)
	pcrSelection := rot.FullPCRSelection()

	if err := a.ExtendPCR(0, []byte("genuine-bootloader-v1.4")); err != nil {
		t.Fatalf("ExtendPCR(0): %v", err)
	}
	if err := a.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")); err != nil {
		t.Fatalf("ExtendPCR(1): %v", err)
	}

	pcrValues, err := root.ReadPCRs(pcrSelection)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	golden := combinedPCRDigest(pcrValues, pcrSelection)

	v.RegisterInstance(instanceID, root.PublicKey(), golden)

	e := enforcement.New(v.PublicKey())
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})

	return &testSystem{
		verifier:     v,
		agent:        a,
		enforcement:  e,
		pcrSelection: pcrSelection,
		instanceID:   instanceID,
	}
}

// bootstrap esegue un ciclo completo di Bootstrap (challenge -> quote ->
// verifica -> token -> routing) e restituisce quote e nonce usati, che i
// test sul replay riutilizzeranno deliberatamente. t.Helper() fa sì che,
// se una delle asserzioni qui dentro fallisce, go test indichi la riga
// del TEST chiamante, non questa riga interna — messaggi di errore più
// utili quando si scorre l'output.
func bootstrap(t *testing.T, sys *testSystem) (*model.QuotePayload, []byte) {
	t.Helper()

	nonce, err := sys.verifier.GenerateNonce(sys.instanceID)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	quote, err := sys.agent.GetTPMQuote(0, nonce, sys.pcrSelection)
	if err != nil {
		t.Fatalf("GetTPMQuote: %v", err)
	}

	if ok := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce); !ok {
		t.Fatal("VerifyQuote deve restituire true per un bootstrap genuino")
	}

	token, err := sys.verifier.IssueToken(sys.instanceID, 0)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	sys.enforcement.UpdateRoutingRules(token)

	return quote, nonce
}

// TestBootstrap verifica la Fase 1: dopo un bootstrap riuscito, il
// routing deve essere consentito. Corrisponde a quanto verificavamo a
// occhio nella sezione "1) BOOTSTRAP" dell'output di main.go.
func TestBootstrap(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys)

	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("il routing deve essere consentito subito dopo un Bootstrap riuscito")
	}
}

// TestContinuousAttestationRinnovaIlToken verifica la Fase 2: un secondo
// giro di challenge/quote/verifica con la STESSA generazione (rinnovo
// della lease) deve avere successo e mantenere il routing aperto.
func TestContinuousAttestationRinnovaIlToken(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys)

	nonce, err := sys.verifier.GenerateNonce(sys.instanceID)
	if err != nil {
		t.Fatalf("GenerateNonce (rinnovo): %v", err)
	}

	quote, err := sys.agent.GetTPMQuote(0, nonce, sys.pcrSelection)
	if err != nil {
		t.Fatalf("GetTPMQuote (rinnovo): %v", err)
	}

	if ok := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce); !ok {
		t.Fatal("VerifyQuote deve restituire true per un rinnovo con la stessa generazione")
	}

	token, err := sys.verifier.IssueToken(sys.instanceID, 0)
	if err != nil {
		t.Fatalf("IssueToken (rinnovo): %v", err)
	}
	sys.enforcement.UpdateRoutingRules(token)

	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("il routing deve restare consentito dopo un rinnovo riuscito")
	}
}

// TestReplayAttackVieneRilevatoERoutingChiusoSubito è il test più
// importante di questo file: verifica non solo che un replay attack
// venga rilevato (VerifyQuote=false), ma che il routing si chiuda
// IMMEDIATAMENTE, senza dover attendere la scadenza naturale del token —
// esattamente il comportamento che abbiamo verificato a mano nell'ultima
// esecuzione di main.go, ora reso permanente come test automatico.
func TestReplayAttackVieneRilevatoERoutingChiusoSubito(t *testing.T) {
	sys := setupTestSystem(t)
	quote, nonce := bootstrap(t, sys)

	// Precondizione esplicita: prima del replay il routing deve essere
	// aperto. Se questa asserzione fallisse, il resto del test non
	// avrebbe senso (staremmo verificando che qualcosa di già chiuso
	// "resti chiuso", il che non proverebbe nulla sulla revoca immediata).
	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("precondizione non soddisfatta: il routing dovrebbe essere aperto prima del replay")
	}

	// Rigiochiamo DELIBERATAMENTE lo stesso quote/nonce del bootstrap,
	// simulando un attaccante che intercetta e ritrasmette il messaggio.
	if replayOK := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce); replayOK {
		t.Fatal("un replay attack non deve mai superare la verifica")
	}

	// Il controllo che conta di più: il routing deve essere già chiuso
	// QUI, nella riga immediatamente successiva a VerifyQuote — non dopo
	// un time.Sleep, non dopo la scadenza del token. Se il canale
	// OnRevoke/Enforcement.Revoke si rompesse in futuro, questa
	// asserzione fallirebbe (mentre BurnRecords più sotto continuerebbe a
	// passare, dato che quel meccanismo non dipende dal canale di
	// notifica) — è quindi il test più mirato possibile su questo
	// specifico meccanismo.
	if sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("dopo un replay rilevato, il routing deve chiudersi IMMEDIATAMENTE (canale di revoca), non restare aperto")
	}

	records := sys.verifier.BurnRecords(sys.instanceID)
	if len(records) != 1 {
		t.Fatalf("atteso esattamente 1 BurnRecord dopo il replay, trovati %d", len(records))
	}
	if records[0].Reason == "" {
		t.Fatal("il BurnRecord deve riportare un motivo non vuoto")
	}

	if _, err := sys.verifier.IssueToken(sys.instanceID, 0); err == nil {
		t.Fatal("IssueToken deve fallire per una generazione bruciata da un replay attack")
	}
}

// TestFailClosedTokenScadutoENonFirmatoCorrettamente verifica la Fase 4
// (comportamento Fail-Closed): un token con ExpiresAt nel passato e firma
// palesemente non valida deve essere rifiutato sia da ValidateToken sia,
// di conseguenza, da IsRoutingAllowed.
func TestFailClosedTokenScadutoENonFirmatoCorrettamente(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys) // porta il sistema in uno stato "con routing valido esistente", per un confronto realistico

	expiredToken := &model.Token{
		InstanceID: sys.instanceID,
		Generation: 0,
		IssuedAt:   time.Now().Add(-2 * time.Minute),
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
		SignatureV: []byte("firma-non-valida-di-test"),
	}

	if sys.enforcement.ValidateToken(expiredToken) {
		t.Fatal("ValidateToken deve rifiutare un token scaduto e con firma non valida")
	}

	sys.enforcement.UpdateRoutingRules(expiredToken)
	if sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("UpdateRoutingRules con un token invalido deve negare il routing, non lasciarlo invariato")
	}
}

// TestFailClosedIstanzaMaiAttestata verifica che un'istanza per cui non è
// mai avvenuto alcun ciclo di attestazione risulti non instradabile per
// default — nessun setup speciale, nessun bootstrap: il default deve
// essere "negato", non "consentito finché non provato il contrario".
func TestFailClosedIstanzaMaiAttestata(t *testing.T) {
	sys := setupTestSystem(t)
	// Notare: NON chiamiamo bootstrap(t, sys) qui — è deliberato, stiamo
	// testando cosa succede PRIMA che qualunque attestazione avvenga.

	if sys.enforcement.IsRoutingAllowed("istanza-completamente-diversa-mai-vista") {
		t.Fatal("un'istanza mai attestata deve risultare non instradabile per default (Fail-Closed)")
	}
}
