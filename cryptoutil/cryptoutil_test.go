// package cryptoutil (white-box, ma qui non serve mai accedere a dettagli
// privati: il package espone già tutto ciò che ci serve testare).
//
// Perché questo file conta più della sua dimensione ridotta farebbe
// pensare: cryptoutil è l'UNICA base crittografica usata dal Verifier per
// firmare/verificare i Token (sk_V/pk_V) — un bug qui non verrebbe quasi
// mai scoperto dagli altri test, perché verifier_test.go/enforcement_test.go
// generano sempre chiavi "coerenti tra loro" (stessa Sign, stessa Verify):
// se Verify avesse un bug che la fa restituire sempre true, ad esempio,
// TUTTI gli altri test continuerebbero a passare comunque, mascherando il
// problema. Solo un test che esercita cryptoutil in isolamento, con dati
// costruiti apposta per far FALLIRE la verifica, può scoprirlo.
package cryptoutil

import "testing"

// TestSignPoiVerifyHaSuccesso è il percorso "felice" base: un messaggio
// firmato con una chiave deve verificare positivamente con la chiave
// pubblica corrispondente.
func TestSignPoiVerifyHaSuccesso(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	messaggio := []byte("contenuto da firmare")
	firma, err := Sign(priv, messaggio)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !Verify(&priv.PublicKey, messaggio, firma) {
		t.Fatal("Verify deve restituire true per una firma valida sul messaggio originale")
	}
}

// TestVerifyRifiutaMessaggioAlterato è il test più importante di questo
// file: verifica che anche un SOLO byte di differenza nel messaggio
// invalidi la firma — è la proprietà di integrità che rende inutile, per
// un attaccante, alterare un Token o una quote dopo la firma.
func TestVerifyRifiutaMessaggioAlterato(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	originale := []byte("contenuto originale")
	firma, err := Sign(priv, originale)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	alterato := []byte("contenuto originalE") // un solo carattere cambiato
	if Verify(&priv.PublicKey, alterato, firma) {
		t.Fatal("Verify non deve accettare una firma valida su un messaggio DIVERSO da quello firmato")
	}
}

// TestVerifyRifiutaChiavePubblicaSbagliata verifica che una firma valida,
// prodotta con una chiave, non venga accettata usando la chiave pubblica
// di una coppia DIVERSA — è il caso concreto che simuliamo anche in
// enforcement_test.go (TestFailClosedFirmaNonValida), qui isolato al solo
// livello crittografico.
func TestVerifyRifiutaChiavePubblicaSbagliata(t *testing.T) {
	privLegittima, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (legittima): %v", err)
	}
	privAttaccante, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (attaccante): %v", err)
	}

	messaggio := []byte("contenuto da firmare")
	firma, err := Sign(privAttaccante, messaggio)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verifichiamo la firma dell'attaccante con la chiave pubblica
	// LEGITTIMA: deve fallire, perché non è quella corrispondente.
	if Verify(&privLegittima.PublicKey, messaggio, firma) {
		t.Fatal("Verify non deve accettare una firma prodotta da una chiave privata diversa da quella pubblica fornita")
	}
}

// TestVerifyRifiutaInputNil verifica i controlli difensivi già presenti
// in Verify (pub o signature nil): non devono causare un panic, devono
// restituire semplicemente false.
func TestVerifyRifiutaInputNil(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	if Verify(nil, []byte("qualcosa"), []byte("firma-qualsiasi")) {
		t.Fatal("Verify con chiave pubblica nil deve restituire false, non causare un panic")
	}
	if Verify(&priv.PublicKey, []byte("qualcosa"), nil) {
		t.Fatal("Verify con firma nil deve restituire false, non causare un panic")
	}
}

// TestSignRifiutaChiaveNil verifica il controllo difensivo già presente
// in Sign: una chiave privata nil deve produrre un errore esplicito, non
// un panic da dereferenziazione di puntatore nil.
func TestSignRifiutaChiaveNil(t *testing.T) {
	if _, err := Sign(nil, []byte("qualcosa")); err == nil {
		t.Fatal("Sign con chiave privata nil deve restituire un errore, non nil")
	}
}

// TestNewNonceProduceValoriDiversiOgniVolta verifica la proprietà minima
// che rende un nonce utile contro i replay attack: due chiamate
// consecutive non devono MAI produrre lo stesso valore. Non è una prova
// crittografica rigorosa di casualità (richiederebbe test statistici ben
// più elaborati, fuori scope qui), ma intercetta bug grossolani come un
// generatore che restituisce sempre zeri o un seed fisso.
func TestNewNonceProduceValoriDiversiOgniVolta(t *testing.T) {
	n1, err := NewNonce(32)
	if err != nil {
		t.Fatalf("NewNonce (1): %v", err)
	}
	n2, err := NewNonce(32)
	if err != nil {
		t.Fatalf("NewNonce (2): %v", err)
	}

	if string(n1) == string(n2) {
		t.Fatal("due chiamate consecutive a NewNonce non devono mai produrre lo stesso valore")
	}
}

// TestNewNonceRispettaLaLunghezzaRichiesta verifica che la dimensione del
// nonce prodotto corrisponda esattamente a quella richiesta — un nonce
// più corto del previsto ridurrebbe silenziosamente la sicurezza contro
// gli attacchi di forza bruta.
func TestNewNonceRispettaLaLunghezzaRichiesta(t *testing.T) {
	n, err := NewNonce(32)
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	if len(n) != 32 {
		t.Fatalf("NewNonce(32) ha prodotto un nonce di %d byte, attesi 32", len(n))
	}
}

// TestNewNonceUsaDefaultConDimensioneNonValida verifica il comportamento
// di default già documentato nel codice: una dimensione <= 0 deve
// produrre comunque un nonce utilizzabile (32 byte di default), non un
// nonce vuoto o un errore.
func TestNewNonceUsaDefaultConDimensioneNonValida(t *testing.T) {
	n, err := NewNonce(0)
	if err != nil {
		t.Fatalf("NewNonce(0): %v", err)
	}
	if len(n) != 32 {
		t.Fatalf("NewNonce(0) doveva usare il default di 32 byte, prodotti %d", len(n))
	}
}
