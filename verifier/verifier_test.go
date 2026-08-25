// Questo file dichiara "package verifier" — LO STESSO package di
// verifier.go, non "verifier_test". Per questo si dice test "white-box"
// (o "internal"): oltre a IssueToken/VerifyQuote/Revoke (esportati, con
// iniziale maiuscola), potremmo qui accedere anche a dettagli PRIVATI del
// package come burnLocked o il campo v.onRevoke — non lo facciamo quasi
// mai in questi test (restiamo il più possibile sull'API pubblica, per
// non legare i test a dettagli interni che potrebbero cambiare), ma è
// bene sapere che la possibilità esiste con questo tipo di package.
//
// NESSUNO di questi test apre una connessione TPM: testano solo la logica
// di business del Verifier che non dipende dalla tecnologia di
// attestazione (hook di revoca, registro dei burn, guardia sui token) —
// per questo sono rapidissimi da eseguire (millisecondi, non decine di
// millisecondi come i test che coinvolgono il simulatore TPM in
// main_test.go).
package verifier

import (
	"testing"

	"ra5g/model"
)

// TestRevokeManualeNotificaGliHookRegistrati verifica il meccanismo di
// notifica introdotto per colmare il gap "Revoca Immediata Routing":
// quando Revoke() viene chiamato, ogni hook registrato con OnRevoke deve
// essere eseguito ESATTAMENTE una volta, con instanceID e generation
// corretti.
func TestRevokeManualeNotificaGliHookRegistrati(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	const generation = 0

	// hookChiamato/hookInstanceID/hookGeneration sono variabili "catturate"
	// dalla closure passata a OnRevoke qui sotto — la funzione anonima
	// "vede" queste variabili dell'ambiente circostante e le modifica
	// quando viene eseguita, permettendoci di verificarle DOPO la
	// chiamata a Revoke.
	var hookChiamato bool
	var hookInstanceID string
	var hookGeneration int

	v.OnRevoke(func(instanceID string, generation int) {
		hookChiamato = true
		hookInstanceID = instanceID
		hookGeneration = generation
	})

	v.Revoke(instanceID, generation, "test manuale")

	if !hookChiamato {
		t.Fatal("l'hook registrato con OnRevoke non è stato chiamato da Revoke")
	}
	if hookInstanceID != instanceID {
		t.Fatalf("hook chiamato con instanceID=%q, atteso %q", hookInstanceID, instanceID)
	}
	if hookGeneration != generation {
		t.Fatalf("hook chiamato con generation=%d, atteso %d", hookGeneration, generation)
	}
}

// TestRevokeNotificaTuttiGliHookRegistrati verifica che, se sono
// registrati PIÙ hook (scenario realistico: in futuro potremmo avere sia
// l'Enforcement sia un sistema di logging/audit iscritti), vengano
// chiamati TUTTI, non solo il primo.
func TestRevokeNotificaTuttiGliHookRegistrati(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var contatore int
	v.OnRevoke(func(string, int) { contatore++ })
	v.OnRevoke(func(string, int) { contatore++ })
	v.OnRevoke(func(string, int) { contatore++ })

	v.Revoke("test-instance", 0, "test")

	if contatore != 3 {
		t.Fatalf("attesi 3 hook eseguiti, eseguiti %d", contatore)
	}
}

// TestIssueTokenFallisceDopoRevoke verifica la guardia già presente in
// IssueToken: una volta che una generazione è stata bruciata (qui tramite
// una revoca manuale, per non dipendere dal TPM), IssueToken deve
// rifiutarsi di emettere un nuovo token per quella stessa generazione.
func TestIssueTokenFallisceDopoRevoke(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	v.Revoke(instanceID, 0, "generazione compromessa")

	if _, err := v.IssueToken(instanceID, 0); err == nil {
		t.Fatal("IssueToken doveva restituire un errore per una generazione bruciata, ha restituito nil")
	}
}

// TestIssueTokenFunzionaPerGenerazioneNonBruciata è il "controllo di
// sanità" complementare al test precedente: verifica che la guardia sulla
// generazione bruciata non blocchi anche generazioni DIVERSE, non
// coinvolte dalla revoca — altrimenti un bug nella guardia potrebbe
// passare inosservato (es. se isBurnedLocked confrontasse solo
// l'instanceID e ignorasse la generation).
func TestIssueTokenFunzionaPerGenerazioneNonBruciata(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	v.Revoke(instanceID, 0, "generazione 0 compromessa")

	// La generazione 1 della STESSA istanza non è mai stata bruciata:
	// IssueToken deve poterla emettere senza problemi.
	if _, err := v.IssueToken(instanceID, 1); err != nil {
		t.Fatalf("IssueToken sulla generazione 1 (mai bruciata) doveva riuscire, errore: %v", err)
	}
}

// TestVerifyQuoteRifiutaIstanzaMaiRegistrata verifica il primissimo
// controllo di VerifyQuote (istanza sconosciuta al Verifier) — un caso
// che non richiede alcuna quote TPM valida per essere testato, perché il
// rifiuto avviene prima ancora di guardare il contenuto della quote.
func TestVerifyQuoteRifiutaIstanzaMaiRegistrata(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Un QuotePayload vuoto va benissimo qui: il Verifier deve fermarsi
	// al controllo di registrazione, prima ancora di provare a
	// deserializzare AttestationBlob (che sarebbe comunque vuoto/non
	// valido). Se questo test fallisse "in profondità" invece che subito,
	// sarebbe un segnale che l'ordine dei controlli in verifyQuoteLocked
	// è stato alterato.
	emptyQuote := model.QuotePayload{}

	if ok := v.VerifyQuote("istanza-mai-vista", emptyQuote, []byte("nonce")); ok {
		t.Fatal("VerifyQuote non deve mai avere successo per un'istanza mai registrata")
	}

	// Nessun BurnRecord deve essere stato creato: un'istanza sconosciuta
	// non è "un attacco da bruciare", è semplicemente fuori dal perimetro
	// di fiducia — non c'è nulla da revocare per un'istanza che non è mai
	// stata ammessa in primo luogo.
	if records := v.BurnRecords("istanza-mai-vista"); len(records) != 0 {
		t.Fatalf("attesi 0 BurnRecords per un'istanza mai registrata, trovati %d", len(records))
	}
}
