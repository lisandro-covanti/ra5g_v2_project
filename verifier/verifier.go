// Package verifier implementa il Verifier ($V$): l'unica entità
// completamente fidata del sistema.
//
// CAMBIO RISPETTO ALLA FASE 1: la parte crittografica di VerifyQuote (era:
// cryptoutil.Verify + bytes.Equal sul digest PCR) è ora DELEGATA a
// server.VerifyAttestation() di google/go-tpm-tools, che sa parsare e
// validare correttamente TPMS_ATTEST/TPMT_SIGNATURE secondo lo standard
// TCG. Tutto il resto — corrispondenza nonce, anti-replay, monotonicità
// delle generazioni, BurnRecords — resta ESATTAMENTE la logica di business
// della Fase 1, perché non ha mai avuto a che fare con la tecnologia TPM:
// è politica del protocollo RA5G definita nel documento di analisi, non
// crittografia.
package verifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmtoolsserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"

	"ra5g/cryptoutil"
	"ra5g/model"
)

// DefaultTokenTTL INVARIATO rispetto alla Fase 1.
const DefaultTokenTTL = 30 * time.Second

// liveEntry INVARIATO rispetto alla Fase 1.
type liveEntry struct {
	Generation int
	ExpiresAt  time.Time
}

// registration contiene i dati di onboarding di un'istanza.
//
// CAMBIO: RoTPublicKey era *rsa.PublicKey nella Fase 1 (unico algoritmo
// simulato); ora è crypto.PublicKey generica perché una AK TPM potrebbe
// essere RSA o ECC a seconda del template usato in fase di provisioning —
// server.VerifyAttestation accetta comunque entrambe tramite la stessa
// interfaccia.
//
// GoldenPCRDigest torna a essere un digest COMBINATO unico (come in
// Fase 1), non più una mappa per-PCR: la prima versione di questo file
// tentava di leggere i valori PCR "puri" da attest.MachineState, ma quel
// messaggio Protobuf è pensato per stati interpretati di alto livello
// (GRUB, EFI, container-optimized OS...) e NON espone una mappa PCR
// generica per un banco SHA-256 arbitrario come il nostro — da cui
// l'errore di compilazione. Il digest combinato, invece, è esattamente il
// campo PCRDigest della struttura standard TCG TPMS_QUOTE_INFO dentro il
// TPMS_ATTEST: lo decodifichiamo direttamente con legacy/tpm2 (vedi sotto),
// che è la superficie di libreria più stabile per questo scopo.
type registration struct {
	AKPublicKey     crypto.PublicKey
	GoldenPCRDigest []byte
}

// Verifier implementa l'entità $V$. Struttura dati INVARIATA rispetto
// alla Fase 1 (stessi campi, stesso significato); cambia solo cosa
// succede DENTRO VerifyQuote.
type Verifier struct {
	mu sync.Mutex

	// privKey/pubKey (sk_V/pk_V) restano deliberatamente RSA software puro:
	// il Verifier è un servizio applicativo ordinario, non un'entità
	// TPM-backed — non c'è alcun motivo per cui la sua chiave operativa
	// debba risiedere in un secure element (a differenza della AK
	// dell'Agent, che DEVE essere TPM-backed per avere senso come RoT).
	privKey *rsa.PrivateKey
	pubKey  *rsa.PublicKey

	registrations map[string]registration
	live          map[string]*liveEntry
	pendingNonces map[string][]byte
	usedNonces    map[string]bool
	burnRecords   map[string][]model.BurnRecord
}

// New crea un nuovo Verifier. INVARIATO nella sostanza rispetto alla
// Fase 1 (sk_V resta RSA software, generata da cryptoutil — vedi il
// commento di testa di cryptoutil/keys.go sul suo ruolo ridotto).
func New() (*Verifier, error) {
	priv, err := cryptoutil.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Verifier{
		privKey:       priv,
		pubKey:        &priv.PublicKey,
		registrations: make(map[string]registration),
		live:          make(map[string]*liveEntry),
		pendingNonces: make(map[string][]byte),
		usedNonces:    make(map[string]bool),
		burnRecords:   make(map[string][]model.BurnRecord),
	}, nil
}

// PublicKey restituisce pk_V, da distribuire (fuori banda, in modo fidato)
// all'Enforcement Plane per la verifica dei token. INVARIATO.
func (v *Verifier) PublicKey() *rsa.PublicKey {
	return v.pubKey
}

// RegisterInstance esegue l'onboarding di un'istanza: associa in modo
// fidato la Attestation Key pubblica e il Golden Measurement (digest PCR
// combinato atteso) che rappresenta lo stato software valido.
//
// NOTA (limite ereditato dal package rot, vedi commento su
// NewTPM2RootOfTrust): questa funzione, come in Fase 1, si fida "per
// definizione" della chiave pubblica passata. In Fase 2 non abbiamo
// ancora aggiunto la verifica EK-cert-chain/ActivateCredential che
// proverebbe che akPub proviene davvero da un TPM genuino — resta un
// lavoro futuro esplicitamente segnalato.
func (v *Verifier) RegisterInstance(instanceID string, akPub crypto.PublicKey, goldenDigest []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.registrations[instanceID] = registration{
		AKPublicKey:     akPub,
		GoldenPCRDigest: goldenDigest,
	}
}

// GenerateNonce INVARIATO rispetto alla Fase 1.
func (v *Verifier) GenerateNonce(instanceID string) ([]byte, error) {
	nonce, err := cryptoutil.NewNonce(32)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.pendingNonces[instanceID] = nonce
	v.mu.Unlock()
	return nonce, nil
}

// VerifyQuote implementa la logica completa di verifica dell'evidenza.
//
// I passi 1-2 (burn/nonce pendente) e 5 (monotonicità) sono ESATTAMENTE
// quelli della Fase 1: pura logica di business del protocollo RA5G,
// indipendente dalla tecnologia di attestazione sottostante. I passi 3-4
// (era: firma RoT + confronto digest PCR) sono ora un'UNICA chiamata a
// server.VerifyAttestation, che sostituisce sia cryptoutil.Verify sia il
// bytes.Equal sul digest — perché in un vero TPMS_ATTEST, la firma copre
// l'intera struttura (incluso ExtraData=nonce e il digest dei PCR
// attestati): non ha senso verificarli separatamente come facevamo noi
// artificialmente in Fase 1.
func (v *Verifier) VerifyQuote(instanceID string, quote model.QuotePayload, expectedNonce []byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	reg, ok := v.registrations[instanceID]
	if !ok {
		return false // istanza mai onboardata: nessuna fiducia possibile
	}

	if v.isBurnedLocked(instanceID, quote.Generation) {
		return false
	}

	// 1. Corrispondenza nonce con la challenge pendente (bookkeeping
	// applicativo NOSTRO, indipendente dal TPM — vedi anche punto 3-4 sotto,
	// dove il nonce viene ri-verificato, stavolta CRITTOGRAFICAMENTE,
	// contro quello firmato dentro il TPMS_ATTEST).
	pending, hasPending := v.pendingNonces[instanceID]
	if !hasPending || !bytes.Equal(pending, expectedNonce) || !bytes.Equal(quote.Nonce, expectedNonce) {
		v.burnLocked(instanceID, quote.Generation, "nonce non corrispondente alla challenge pendente")
		return false
	}

	// 2. Anti-replay applicativo: stesso meccanismo della Fase 1.
	nonceKey := hex.EncodeToString(quote.Nonce)
	if v.usedNonces[nonceKey] {
		v.burnLocked(instanceID, quote.Generation, "replay attack: nonce già consumato")
		return false
	}

	// 3. Deserializza il messaggio Attestation (Protobuf) trasportato nel
	// blob applicativo, poi delega a server.VerifyAttestation la verifica
	// crittografica TPM-standard: firma TPMT_SIGNATURE valida rispetto
	// alla AK registrata, ExtraData del TPMS_ATTEST coincidente col nonce
	// atteso, coerenza interna tra event log e digest dei PCR quotati. Il
	// MachineState restituito (stato interpretato ad alto livello: GRUB,
	// EFI, ecc.) non ci serve per il confronto PCR — lo ignoriamo
	// esplicitamente con "_" e passiamo al punto 4 per il confronto
	// granulare del digest PCR grezzo.
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(quote.AttestationBlob, &attestation); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("attestation blob non decodificabile: %v", err))
		return false
	}

	_, err := tpmtoolsserver.VerifyAttestation(&attestation, tpmtoolsserver.VerifyOpts{
		Nonce:      expectedNonce,
		TrustedAKs: []crypto.PublicKey{reg.AKPublicKey},
	})
	if err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("verifica TPM fallita: %v", err))
		return false
	}

	// 4. Confronto del digest PCR con il Golden Measurement di riferimento.
	// Il MachineState di go-tpm-tools non espone una mappa PCR grezza per
	// banchi generici (vedi commento su "registration" più sopra); quindi
	// estraiamo il PCRDigest direttamente dal TPMS_ATTEST usando
	// legacy/tpm2.DecodeAttestationData — la stessa struttura standard TCG
	// che TPM2_Quote produce e firma, quindi già implicitamente
	// autenticata dalla verifica di firma appena eseguita al punto 3
	// (stiamo decodificando lo STESSO blob la cui firma è già stata
	// validata, non un input non fidato separato).
	//
	// attestation.GetQuotes() contiene una quote per ciascun banco PCR
	// supportato (tipicamente SHA-1 e SHA-256): cerchiamo quella sul
	// banco SHA-256, coerente con come abbiamo letto il Golden Measurement
	// in fase di onboarding (vedi rot.TPM2RootOfTrust.ReadPCRs).
	var actualDigest []byte
	for _, q := range attestation.GetQuotes() {
		ad, decodeErr := tpm2.DecodeAttestationData(q.GetQuote())
		if decodeErr != nil || ad.AttestedQuoteInfo == nil {
			continue
		}
		if ad.AttestedQuoteInfo.PCRSelection.Hash == tpm2.AlgSHA256 {
			actualDigest = ad.AttestedQuoteInfo.PCRDigest
			break
		}
	}
	if actualDigest == nil {
		v.burnLocked(instanceID, quote.Generation, "nessuna quote SHA-256 valida trovata nell'attestazione")
		return false
	}
	if !bytes.Equal(actualDigest, reg.GoldenPCRDigest) {
		v.burnLocked(instanceID, quote.Generation, "mismatch PCR rispetto al Golden Measurement")
		return false
	}

	// 5. Generation Exclusivity & Monotonicity: INVARIATO rispetto alla
	// Fase 1, identico ragionamento (rinnovo stessa generazione ok,
	// rollback a generazione inferiore vietato).
	if entry, exists := v.live[instanceID]; exists && quote.Generation < entry.Generation {
		v.burnLocked(instanceID, quote.Generation, "violazione di monotonicità: generazione inferiore a quella live")
		return false
	}

	v.usedNonces[nonceKey] = true
	return true
}

// IssueToken INVARIATO rispetto alla Fase 1: firma con sk_V (RSA software),
// non ha nulla a che fare con la tecnologia TPM.
func (v *Verifier) IssueToken(instanceID string, generation int) (*model.Token, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isBurnedLocked(instanceID, generation) {
		return nil, errors.New("verifier: impossibile emettere token per una generazione bruciata")
	}

	now := time.Now()
	token := &model.Token{
		InstanceID: instanceID,
		Generation: generation,
		IssuedAt:   now,
		ExpiresAt:  now.Add(DefaultTokenTTL),
	}
	sig, err := cryptoutil.Sign(v.privKey, token.SignedBytes())
	if err != nil {
		return nil, err
	}
	token.SignatureV = sig

	v.live[instanceID] = &liveEntry{Generation: generation, ExpiresAt: token.ExpiresAt}
	return token, nil
}

// Revoke, burnLocked, isBurnedLocked, BurnRecords: TUTTI INVARIATI rispetto
// alla Fase 1 — pura gestione dello stato interno del Verifier, zero
// dipendenze dalla tecnologia di attestazione.
func (v *Verifier) Revoke(instanceID string, generation int, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.burnLocked(instanceID, generation, reason)
}

func (v *Verifier) burnLocked(instanceID string, generation int, reason string) {
	v.burnRecords[instanceID] = append(v.burnRecords[instanceID], model.BurnRecord{
		InstanceID: instanceID,
		Generation: generation,
		RevokedAt:  time.Now(),
		Reason:     reason,
	})
	if entry, ok := v.live[instanceID]; ok && entry.Generation == generation {
		delete(v.live, instanceID)
	}
	delete(v.pendingNonces, instanceID)
}

func (v *Verifier) isBurnedLocked(instanceID string, generation int) bool {
	for _, rec := range v.burnRecords[instanceID] {
		if rec.Generation == generation {
			return true
		}
	}
	return false
}

func (v *Verifier) BurnRecords(instanceID string) []model.BurnRecord {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]model.BurnRecord, len(v.burnRecords[instanceID]))
	copy(out, v.burnRecords[instanceID])
	return out
}
