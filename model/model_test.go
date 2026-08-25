// package model (white-box).
//
// Questi test riguardano SOLO le funzioni SignedBytes() di Token e
// GenerationLinkCert — la codifica canonica su cui il Verifier calcola la
// firma sk_V. Il rischio specifico che vogliamo escludere è la
// COLLISIONE DI CODIFICA: se due valori diversi di una struct (es.
// Generation=0 vs Generation=1) producessero, per un bug di
// concatenazione, la STESSA sequenza di byte in output da SignedBytes(),
// allora una firma calcolata per un Token sarebbe (erroneamente) valida
// anche per un Token con un campo diverso — un problema di sicurezza
// sottile, difficile da notare leggendo il codice, ma facile da
// verificare con un test mirato come questo.
package model

import (
	"testing"
	"time"
)

// TestTokenSignedBytesCambiaConGeneration verifica che cambiare SOLO il
// campo Generation produca una codifica diversa — altrimenti un
// attaccante potrebbe prendere un Token firmato per la generazione 0 e
// "farlo passare" per la generazione 1 senza invalidare la firma.
func TestTokenSignedBytesCambiaConGeneration(t *testing.T) {
	base := Token{
		InstanceID: "vnf-1",
		Generation: 0,
		IssuedAt:   time.Unix(1000, 0),
		ExpiresAt:  time.Unix(2000, 0),
	}
	variante := base
	variante.Generation = 1

	if string(base.SignedBytes()) == string(variante.SignedBytes()) {
		t.Fatal("Token con Generation diversa devono produrre SignedBytes() diversi")
	}
}

// TestTokenSignedBytesCambiaConInstanceID verifica lo stesso principio
// per il campo InstanceID — un Token per un'istanza non deve poter essere
// "riattribuito" a un'altra istanza senza invalidare la firma.
func TestTokenSignedBytesCambiaConInstanceID(t *testing.T) {
	base := Token{
		InstanceID: "vnf-1",
		Generation: 0,
		IssuedAt:   time.Unix(1000, 0),
		ExpiresAt:  time.Unix(2000, 0),
	}
	variante := base
	variante.InstanceID = "vnf-2"

	if string(base.SignedBytes()) == string(variante.SignedBytes()) {
		t.Fatal("Token con InstanceID diverso devono produrre SignedBytes() diversi")
	}
}

// TestTokenSignedBytesCambiaConExpiresAt verifica lo stesso principio per
// la scadenza: un attaccante non deve poter "estendere" la validità di un
// Token già firmato modificando ExpiresAt senza invalidare la firma —
// è esattamente la proprietà su cui si basa il comportamento Fail-Closed
// dell'Enforcement Plane.
func TestTokenSignedBytesCambiaConExpiresAt(t *testing.T) {
	base := Token{
		InstanceID: "vnf-1",
		Generation: 0,
		IssuedAt:   time.Unix(1000, 0),
		ExpiresAt:  time.Unix(2000, 0),
	}
	variante := base
	variante.ExpiresAt = time.Unix(999999, 0) // scadenza spostata molto nel futuro

	if string(base.SignedBytes()) == string(variante.SignedBytes()) {
		t.Fatal("Token con ExpiresAt diverso devono produrre SignedBytes() diversi")
	}
}

// TestTokenSignedBytesDeterministico verifica che, a parità di contenuto,
// SignedBytes() produca SEMPRE lo stesso output — necessario perché
// Verifier (che firma) e chiunque verifichi la firma in futuro concordino
// bit per bit sulla stessa codifica.
func TestTokenSignedBytesDeterministico(t *testing.T) {
	token := Token{
		InstanceID: "vnf-1",
		Generation: 3,
		IssuedAt:   time.Unix(1000, 0),
		ExpiresAt:  time.Unix(2000, 0),
	}

	if string(token.SignedBytes()) != string(token.SignedBytes()) {
		t.Fatal("SignedBytes() deve essere deterministico: stesso Token, stesso output, sempre")
	}
}

// TestGenerationLinkCertSignedBytesCambiaConTargetHost verifica la stessa
// proprietà anti-collisione per GenerationLinkCert (usato dalla futura
// Fase 3, Migrazione): un certificato di collegamento tra generazioni non
// deve poter essere "dirottato" verso un host di destinazione diverso da
// quello originariamente firmato.
func TestGenerationLinkCertSignedBytesCambiaConTargetHost(t *testing.T) {
	base := GenerationLinkCert{
		InstanceID:    "vnf-1",
		OldGeneration: 0,
		NewGeneration: 1,
		MigNonce:      []byte("nonce-migrazione"),
		TargetHost:    "host-a.esempio.local",
	}
	variante := base
	variante.TargetHost = "host-attaccante.esempio.local"

	if string(base.SignedBytes()) == string(variante.SignedBytes()) {
		t.Fatal("GenerationLinkCert con TargetHost diverso devono produrre SignedBytes() diversi")
	}
}

// TestGenerationLinkCertSignedBytesCambiaConGenerazioni verifica che
// scambiare OldGeneration/NewGeneration (es. 0->1 vs 1->0) produca
// codifiche diverse — un dettaglio non ovvio: se la codifica concatenasse
// i due numeri senza separatore o lunghezza fissa, "01" e "10" letti come
// stringhe potrebbero collidere in modi inattesi con altri campi. Il
// codice usa già una codifica a 8 byte fissi per intero (vedi
// binary.BigEndian.PutUint64 in types.go), quindi ci aspettiamo che
// questo test passi — è comunque la verifica esplicita di quella scelta.
func TestGenerationLinkCertSignedBytesCambiaConGenerazioni(t *testing.T) {
	a := GenerationLinkCert{
		InstanceID:    "vnf-1",
		OldGeneration: 0,
		NewGeneration: 1,
		MigNonce:      []byte("nonce"),
		TargetHost:    "host",
	}
	b := GenerationLinkCert{
		InstanceID:    "vnf-1",
		OldGeneration: 1,
		NewGeneration: 0,
		MigNonce:      []byte("nonce"),
		TargetHost:    "host",
	}

	if string(a.SignedBytes()) == string(b.SignedBytes()) {
		t.Fatal("scambiare OldGeneration/NewGeneration deve produrre SignedBytes() diversi")
	}
}
