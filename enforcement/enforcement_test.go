// Come verifier_test.go, anche questo file dichiara "package enforcement"
// (white-box). Nessuno di questi test coinvolge il TPM: l'Enforcement
// Plane non ha mai avuto a che fare con quella tecnologia (lo abbiamo
// verificato più volte durante lo sviluppo), quindi possiamo testarlo
// completamente da solo, costruendo a mano dei Token firmati con una
// coppia di chiavi RSA "usa e getta" generata da cryptoutil — lo stesso
// meccanismo che userebbe un vero Verifier, ma senza bisogno di
// istanziarne uno completo.
package enforcement

import (
	"crypto/rsa"
	"testing"
	"time"

	"ra5g/cryptoutil"
	"ra5g/model"
)

// signedToken è una piccola funzione helper (non un test: non inizia per
// "Test", "go test" la ignora come tale) che costruisce e firma un Token
// valido, per non dover ripetere le stesse 6-7 righe in ogni test. Il
// parametro ttl permette ai singoli test di creare token già scaduti,
// passando una durata negativa.
func signedToken(t *testing.T, priv *rsa.PrivateKey, instanceID string, generation int, ttl time.Duration) *model.Token {
	t.Helper() // se una t.Fatalf qui dentro scatta, l'errore punta al chiamante, non a questa riga

	now := time.Now()
	token := &model.Token{
		InstanceID: instanceID,
		Generation: generation,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
	}
	sig, err := cryptoutil.Sign(priv, token.SignedBytes())
	if err != nil {
		t.Fatalf("cryptoutil.Sign: %v", err)
	}
	token.SignatureV = sig
	return token
}

// newTestKeyPair genera la coppia di chiavi RSA "usa e getta" che simula
// sk_V/pk_V del Verifier in questi test — l'Enforcement Plane, per
// design, non genera mai le proprie chiavi: le riceve fuori banda da un
// Verifier fidato, qui rappresentato semplicemente da questa coppia.
func newTestKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := cryptoutil.GenerateKeyPair()
	if err != nil {
		t.Fatalf("cryptoutil.GenerateKeyPair: %v", err)
	}
	return priv
}

// TestUpdateRoutingRulesAmmetteTokenValido verifica il percorso base
// "felice": un token valido, non scaduto, correttamente firmato, deve
// abilitare il routing.
func TestUpdateRoutingRulesAmmetteTokenValido(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	token := signedToken(t, priv, "vnf-1", 0, 30*time.Second)
	e.UpdateRoutingRules(token)

	if !e.IsRoutingAllowed("vnf-1") {
		t.Fatal("il routing deve essere consentito dopo un token valido e non scaduto")
	}
}

// TestFailClosedTokenScaduto verifica la proprietà "Fail-Closed Default":
// un token con firma valida ma ExpiresAt nel passato deve essere
// rifiutato, non semplicemente "consentito finché qualcuno non se ne
// accorge".
func TestFailClosedTokenScaduto(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	// ttl negativo: ExpiresAt finisce nel passato rispetto a IssuedAt/now.
	token := signedToken(t, priv, "vnf-1", 0, -1*time.Minute)

	if e.ValidateToken(token) {
		t.Fatal("ValidateToken deve rifiutare un token già scaduto")
	}

	e.UpdateRoutingRules(token)
	if e.IsRoutingAllowed("vnf-1") {
		t.Fatal("il routing non deve mai essere consentito con un token scaduto")
	}
}

// TestFailClosedFirmaNonValida verifica che un token con contenuto
// corretto ma FIRMA sbagliata (qui: firmato con una chiave diversa da
// quella registrata presso l'Enforcement) venga rifiutato — non basta che
// il token "sembri" valido nei suoi campi.
func TestFailClosedFirmaNonValida(t *testing.T) {
	privRegistrata := newTestKeyPair(t)
	privAttaccante := newTestKeyPair(t) // chiave DIVERSA, mai comunicata all'Enforcement

	e := New(&privRegistrata.PublicKey)

	// Il token è firmato con la chiave dell'attaccante, non con quella
	// che l'Enforcement conosce come legittima (pk_V del Verifier vero).
	token := signedToken(t, privAttaccante, "vnf-1", 0, 30*time.Second)

	if e.ValidateToken(token) {
		t.Fatal("ValidateToken deve rifiutare un token firmato con una chiave non registrata")
	}
}

// TestFailClosedIstanzaMaiVista verifica che, per un'istanza per cui
// UpdateRoutingRules non è MAI stato chiamato con successo, il routing
// risulti negato per default — è il cuore del principio "Fail-Closed":
// l'assenza di una regola esplicita NON equivale a "consentito".
func TestFailClosedIstanzaMaiVista(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	if e.IsRoutingAllowed("istanza-mai-vista") {
		t.Fatal("un'istanza per cui non è mai stata installata una regola di routing deve risultare non instradabile")
	}
}

// TestGenerationExclusivityRifiutaGenerazioneInferiore verifica che,
// dopo aver ammesso la generazione 1, un token per la generazione 0
// (precedente) della STESSA istanza venga rifiutato — protezione da
// rollback/downgrade.
func TestGenerationExclusivityRifiutaGenerazioneInferiore(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	tokenGen1 := signedToken(t, priv, "vnf-1", 1, 30*time.Second)
	e.UpdateRoutingRules(tokenGen1)

	tokenGen0 := signedToken(t, priv, "vnf-1", 0, 30*time.Second)
	if e.ValidateToken(tokenGen0) {
		t.Fatal("ValidateToken deve rifiutare un token per una generazione inferiore a quella già ammessa (violazione di Generation Exclusivity)")
	}
}

// TestRevokeNegaSubitoIlRouting è il test che verifica DIRETTAMENTE il
// canale di revoca immediata introdotto per colmare il gap "Revoca
// Immediata Routing": senza aspettare alcuna scadenza, una chiamata
// esplicita a Revoke deve interrompere il routing sul colpo.
func TestRevokeNegaSubitoIlRouting(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	// Token con TTL lungo: se Revoke funzionasse "per scadenza naturale"
	// invece che immediatamente, questo test fallirebbe (il routing
	// resterebbe aperto per un'ora).
	token := signedToken(t, priv, "vnf-1", 0, 1*time.Hour)
	e.UpdateRoutingRules(token)

	if !e.IsRoutingAllowed("vnf-1") {
		t.Fatal("precondizione non soddisfatta: il routing dovrebbe essere consentito prima della revoca")
	}

	e.Revoke("vnf-1", 0)

	if e.IsRoutingAllowed("vnf-1") {
		t.Fatal("dopo Revoke(), il routing deve essere negato IMMEDIATAMENTE, non attendere la scadenza del token (che qui è tra un'ora)")
	}
}

// TestRevokeIgnoraGenerazioneOrmaiSuperata verifica la guardia contro
// notifiche "in ritardo" aggiunta a Enforcement.Revoke: se l'istanza è
// GIÀ passata a una generazione più recente di quella indicata nella
// revoca, il routing della generazione ATTUALE non deve essere toccato.
func TestRevokeIgnoraGenerazioneOrmaiSuperata(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	// L'istanza è già alla generazione 1 (es. dopo una migrazione riuscita).
	tokenGen1 := signedToken(t, priv, "vnf-1", 1, 30*time.Second)
	e.UpdateRoutingRules(tokenGen1)

	// Arriva una revoca riferita alla VECCHIA generazione 0 — scenario
	// realistico se un evento di burn generato prima della migrazione
	// viene notificato con un certo ritardo.
	e.Revoke("vnf-1", 0)

	if !e.IsRoutingAllowed("vnf-1") {
		t.Fatal("una revoca riferita a una generazione ormai superata non deve interrompere il routing della generazione attuale")
	}
}

// TestRevokeIstanzaSenzaRegoleNonPanica verifica solo che Revoke() su
// un'istanza per cui non esiste alcuna regola di routing non causi un
// panic (es. un accesso a mappa non inizializzata) — un caso limite ma
// realistico se il Verifier notifica un burn per un'istanza il cui primo
// Bootstrap è già fallito, prima che UpdateRoutingRules sia mai stato
// chiamato con successo.
func TestRevokeIstanzaSenzaRegoleNonPanica(t *testing.T) {
	priv := newTestKeyPair(t)
	e := New(&priv.PublicKey)

	e.Revoke("istanza-mai-vista", 0) // non deve panicare

	if e.IsRoutingAllowed("istanza-mai-vista") {
		t.Fatal("un'istanza mai vista deve restare non instradabile anche dopo una Revoke() su di essa")
	}
}
