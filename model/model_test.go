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

// I test seguenti riguardano ContextBoundNonce, introdotta per il
// meccanismo di context-binding del nonce: stessa logica anti-collisione
// applicata sopra a Token/GenerationLinkCert, qui applicata alla funzione
// che lega insieme tag, instanceID, generation e nonce prima che il TPM
// lo firmi (vedi agent.go/verifier.go).

// TestContextBoundNonceDeterministico verifica che, a parità di input,
// ContextBoundNonce produca sempre lo stesso output — necessario perché
// Agent (che lo calcola prima della firma) e Verifier (che lo ricalcola
// prima della verifica) DEVONO ottenere bit per bit lo stesso valore.
func TestContextBoundNonceDeterministico(t *testing.T) {
	nonce := []byte("nonce-di-esempio")

	a := ContextBoundNonce(ContextTagBoot, "vnf-1", 0, nonce)
	b := ContextBoundNonce(ContextTagBoot, "vnf-1", 0, nonce)

	if string(a) != string(b) {
		t.Fatal("ContextBoundNonce deve essere deterministico: stessi input, stesso output, sempre")
	}
}

// TestContextBoundNonceCambiaConTag è la proprietà di sicurezza centrale
// del context-binding: a parità di tutto il resto, un tag diverso deve
// produrre un valore diverso — altrimenti una quote prodotta per un
// contesto (es. Renew) potrebbe essere accettata anche per un contesto
// diverso (es. Migrate) semplicemente cambiando il campo Tag dichiarato,
// senza che il TPM se ne accorga.
func TestContextBoundNonceCambiaConTag(t *testing.T) {
	nonce := []byte("stesso-nonce")

	boot := ContextBoundNonce(ContextTagBoot, "vnf-1", 0, nonce)
	renew := ContextBoundNonce(ContextTagRenew, "vnf-1", 0, nonce)
	migrate := ContextBoundNonce(ContextTagMigrate, "vnf-1", 0, nonce)

	if string(boot) == string(renew) || string(boot) == string(migrate) || string(renew) == string(migrate) {
		t.Fatal("tag diversi devono produrre ContextBoundNonce diversi, a parità di instanceID/generation/nonce")
	}
}

// TestContextBoundNonceCambiaConInstanceID verifica che una quote
// prodotta per un'istanza non possa essere "riattribuita" a un'altra
// istanza semplicemente dichiarando un InstanceID diverso nel QuotePayload.
func TestContextBoundNonceCambiaConInstanceID(t *testing.T) {
	nonce := []byte("stesso-nonce")

	a := ContextBoundNonce(ContextTagBoot, "vnf-1", 0, nonce)
	b := ContextBoundNonce(ContextTagBoot, "vnf-2", 0, nonce)

	if string(a) == string(b) {
		t.Fatal("instanceID diversi devono produrre ContextBoundNonce diversi")
	}
}

// TestContextBoundNonceCambiaConGeneration verifica che una quote
// prodotta per una generazione non possa essere presentata come valida
// per una generazione diversa della stessa istanza.
func TestContextBoundNonceCambiaConGeneration(t *testing.T) {
	nonce := []byte("stesso-nonce")

	a := ContextBoundNonce(ContextTagBoot, "vnf-1", 0, nonce)
	b := ContextBoundNonce(ContextTagBoot, "vnf-1", 1, nonce)

	if string(a) == string(b) {
		t.Fatal("generation diverse devono produrre ContextBoundNonce diversi")
	}
}

// TestContextBoundNonceInstanceIDLunghezzaVariabileNonCollide è un test
// mirato sulla scelta di codifica: instanceID è l'unico campo di
// lunghezza variabile che precede altri campi in ContextBoundNonce, per
// questo la funzione lo prefissa con la sua lunghezza (vedi il commento
// in types.go). Senza quel prefisso, concatenare "ab"+"c" e "a"+"bc"
// darebbe la stessa sequenza di byte "abc" — questo test costruisce
// esattamente quel caso limite per verificare che la codifica a
// lunghezza esplicita lo prevenga.
func TestContextBoundNonceInstanceIDLunghezzaVariabileNonCollide(t *testing.T) {
	nonce := []byte("nonce-fisso")

	// Caso A: instanceID="ab", generation=0 (le cifre di "generation"
	// sono comunque codificate a lunghezza fissa da binary.BigEndian, ma
	// costruiamo instanceID in modo che, SENZA length-prefix, "ab"+resto
	// e "a"+"b"+resto potrebbero confondersi).
	a := ContextBoundNonce(ContextTagBoot, "ab", 0, nonce)
	b := ContextBoundNonce(ContextTagBoot, "a", 0, append([]byte("b"), nonce...))

	if string(a) == string(b) {
		t.Fatal("la codifica di ContextBoundNonce non deve permettere collisioni tra instanceID e nonce di lunghezza diversa ma concatenazione simile")
	}
}

// I test seguenti riguardano MigrationSourceBoundNonce (Fase 3): stessa
// logica anti-collisione applicata sopra, qui sulla funzione che lega la
// quote dell'istanza USCENTE durante una migrazione anche all'host di
// destinazione — il campo aggiuntivo rispetto a ContextBoundNonce.

// TestMigrationSourceBoundNonceDeterministico verifica che, a parità di
// input, la funzione produca sempre lo stesso output — necessario perché
// Agent (che la calcola prima della firma, in GetMigrationSourceQuote) e
// Verifier (che la ricalcola in validateMigrationSourceLocked) devono
// ottenere bit per bit lo stesso valore.
func TestMigrationSourceBoundNonceDeterministico(t *testing.T) {
	nonce := []byte("nonce-migrazione")

	a := MigrationSourceBoundNonce("vnf-1", 0, nonce, "host-a")
	b := MigrationSourceBoundNonce("vnf-1", 0, nonce, "host-a")

	if string(a) != string(b) {
		t.Fatal("MigrationSourceBoundNonce deve essere deterministico: stessi input, stesso output, sempre")
	}
}

// TestMigrationSourceBoundNonceCambiaConTargetHost è la proprietà di
// sicurezza centrale di questa funzione: a parità di tutto il resto, un
// host di destinazione diverso deve produrre un valore diverso —
// altrimenti una quote con cui un'istanza acconsente a migrare verso
// l'host A potrebbe essere presentata al Verifier come valida anche per
// una migrazione verso l'host B.
func TestMigrationSourceBoundNonceCambiaConTargetHost(t *testing.T) {
	nonce := []byte("nonce-migrazione")

	a := MigrationSourceBoundNonce("vnf-1", 0, nonce, "host-a.esempio.local")
	b := MigrationSourceBoundNonce("vnf-1", 0, nonce, "host-attaccante.esempio.local")

	if string(a) == string(b) {
		t.Fatal("host di destinazione diversi devono produrre MigrationSourceBoundNonce diversi")
	}
}

// TestMigrationSourceBoundNonceCambiaConOldGeneration verifica che una
// quote di migrazione prodotta per una generazione uscente non possa
// essere presentata come valida per una generazione diversa della stessa
// istanza (stessa proprietà già verificata per ContextBoundNonce, qui
// applicata al campo OldGeneration).
func TestMigrationSourceBoundNonceCambiaConOldGeneration(t *testing.T) {
	nonce := []byte("nonce-migrazione")

	a := MigrationSourceBoundNonce("vnf-1", 0, nonce, "host-a")
	b := MigrationSourceBoundNonce("vnf-1", 1, nonce, "host-a")

	if string(a) == string(b) {
		t.Fatal("oldGeneration diverse devono produrre MigrationSourceBoundNonce diversi")
	}
}

// TestMigrationSourceBoundNonceCambiaConInstanceID verifica che una quote
// di migrazione non possa essere "riattribuita" a un'istanza diversa da
// quella che l'ha realmente prodotta.
func TestMigrationSourceBoundNonceCambiaConInstanceID(t *testing.T) {
	nonce := []byte("nonce-migrazione")

	a := MigrationSourceBoundNonce("vnf-1", 0, nonce, "host-a")
	b := MigrationSourceBoundNonce("vnf-2", 0, nonce, "host-a")

	if string(a) == string(b) {
		t.Fatal("instanceID diversi devono produrre MigrationSourceBoundNonce diversi")
	}
}

// TestMigrationSourceBoundNonceDiversoDaContextBoundNonce verifica che,
// a parità di tag/instanceID/generation/nonce, MigrationSourceBoundNonce
// (che include anche targetHost) e ContextBoundNonce (che non lo include)
// producano valori DIVERSI — altrimenti una quote di Bootstrap/Renew
// potrebbe, in teoria, risultare accettabile anche come quote di
// migrazione o viceversa, semplicemente perché le due funzioni
// producessero output identici quando targetHost è vuoto.
func TestMigrationSourceBoundNonceDiversoDaContextBoundNonce(t *testing.T) {
	nonce := []byte("stesso-nonce")

	migrazione := MigrationSourceBoundNonce("vnf-1", 0, nonce, "")
	generico := ContextBoundNonce(ContextTagMigrate, "vnf-1", 0, nonce)

	if string(migrazione) == string(generico) {
		t.Fatal("MigrationSourceBoundNonce e ContextBoundNonce devono produrre valori diversi anche a parità di tag/instanceID/generation/nonce (targetHost vuoto incluso)")
	}
}
