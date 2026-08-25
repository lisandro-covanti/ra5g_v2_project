// Package cryptoutil fornisce funzioni di supporto per generare coppie di
// chiavi asimmetriche, firmare e verificare payload.
//
// FASE 2 — cambio di ruolo importante rispetto alla Fase 1: queste funzioni
// NON vengono più usate per simulare il RoT/TPM (quella responsabilità è
// passata al package "rot", che si appoggia a google/go-tpm-tools per
// parlare con un TPM 2.0 reale o emulato). cryptoutil resta in uso SOLO
// per le operazioni crittografiche del Verifier stesso (sk_V/pk_V), che è
// un servizio software ordinario e non ha alcun motivo di essere vincolato
// a un TPM: firma e verifica dei Token restano RSA software puro.
package cryptoutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// KeySize definisce la dimensione delle chiavi RSA simulate.
const KeySize = 2048

// GenerateKeyPair genera una nuova coppia di chiavi RSA.
// In Fase 2 questa funzione sarà sostituita da TPM2_CreatePrimary /
// TPM2_Create per generare chiavi vincolate all'hardware.
func GenerateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, KeySize)
}

// Sign calcola SHA-256(data) e produce una firma PKCS#1 v1.5.
// In Fase 2 questa operazione corrisponde a TPM2_Sign eseguito internamente
// al TPM sulla chiave protetta dall'hardware (sk_RoT o sk_V).
func Sign(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("cryptoutil: chiave privata nil")
	}
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
}

// Verify verifica una firma PKCS#1 v1.5 su SHA-256(data).
func Verify(pub *rsa.PublicKey, data, signature []byte) bool {
	if pub == nil || signature == nil {
		return false
	}
	digest := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature)
	return err == nil
}

// NewNonce genera un nonce crittograficamente sicuro di lunghezza fissata.
func NewNonce(size int) ([]byte, error) {
	if size <= 0 {
		size = 32
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
