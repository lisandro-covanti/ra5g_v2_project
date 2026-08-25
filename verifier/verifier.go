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
//
// AGGIORNAMENTO SUCCESSIVO (canale di revoca immediata): in precedenza,
// quando il Verifier bruciava una generazione, l'Enforcement Plane non
// veniva mai avvisato attivamente — il routing decadeva solo alla
// scadenza naturale del token (fino a DefaultTokenTTL). Questo file
// introduce un meccanismo di "hook" (funzioni registrate da main.go
// tramite OnRevoke e richiamate da questo Verifier quando serve) per
// notificare l'Enforcement nello stesso istante in cui un burn avviene,
// colmando il gap segnalato dal passo "Revoca Immediata Routing" della
// Fase 4 del sequence diagram del protocollo. Per la spiegazione completa
// di COME questo evita un deadlock sul mutex del Verifier, vedi i
// commenti su VerifyQuote/verifyQuoteLocked/fireRevokeHooks più sotto.
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

	// onRevoke contiene gli "hook" (funzioni salvate per essere richiamate
	// più tardi, non chiamate qui) da eseguire ogni volta che il Verifier
	// invalida permanentemente una generazione. Il pattern completo è
	// spiegato nel commento sopra fireRevokeHooks più sotto — qui basti
	// sapere che si tratta di un semplice slice di funzioni, popolato in
	// fase di setup da main.go tramite OnRevoke(), MAI durante la verifica
	// vera e propria.
	onRevoke []func(instanceID string, generation int)
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

// VerifyQuote è il punto d'ingresso PUBBLICO per la verifica di una quote.
//
// AGGIORNAMENTO rispetto alla versione precedente di questo file: prima,
// tutta la logica di verifica E la gestione del lock stavano in questa
// stessa funzione. Ora VerifyQuote è diventata un "guscio sottile" (thin
// wrapper): delega l'intera logica (nonce, anti-replay, verifica TPM,
// monotonicità...) alla funzione privata verifyQuoteLocked, che si occupa
// anche di acquisire/rilasciare v.mu esattamente come prima. Il motivo di
// questa separazione è poter notificare gli "hook" di revoca (vedi
// OnRevoke più sotto) SOLO DOPO che il lock è stato rilasciato — mai
// mentre è ancora acquisito.
//
// PERCHÉ QUESTO CONTA (deadlock): sync.Mutex in Go NON è rientrante (a
// differenza di ReentrantLock in Java): se una goroutine che possiede già
// v.mu provasse a fare di nuovo v.mu.Lock(), resterebbe bloccata per
// sempre — in pratica, aspetterebbe se stessa. Se chiamassimo gli hook
// DA DENTRO la sezione protetta dal lock, e un domani uno di quegli hook
// (direttamente o indirettamente) richiamasse un metodo del Verifier che
// fa v.mu.Lock(), il programma si bloccherebbe in modo silenzioso e
// difficile da diagnosticare. Separare "decidere e registrare lo stato"
// (sotto lock, in verifyQuoteLocked) da "avvisare il mondo esterno" (fuori
// dal lock, qui) elimina strutturalmente questo rischio, invece di
// affidarsi alla disciplina di chi scriverà gli hook in futuro.
func (v *Verifier) VerifyQuote(instanceID string, quote model.QuotePayload, expectedNonce []byte) bool {
	// verifyQuoteLocked "fa risalire" fuori dal lock l'informazione su
	// COSA è successo, non solo SE la verifica è riuscita: da qui in poi
	// possiamo decidere se notificare gli hook, con la certezza che il
	// lock del Verifier (v.mu) è già stato rilasciato (il suo
	// "defer v.mu.Unlock()" interno è scattato non appena la funzione è
	// tornata, PRIMA che l'esecuzione arrivi a questa riga).
	ok, revokedGeneration, wasRevoked := v.verifyQuoteLocked(instanceID, quote, expectedNonce)

	if wasRevoked {
		v.fireRevokeHooks(instanceID, revokedGeneration)
	}

	return ok
}

// verifyQuoteLocked contiene la logica di verifica vera e propria,
// INVARIATA nella sostanza rispetto alla versione precedente (stessi 5
// passi: burn pregresso, nonce pendente, anti-replay, verifica TPM +
// confronto Golden Measurement, monotonicità). L'unico cambiamento è nella
// firma di ritorno:
//
//   - ok: l'esito della verifica, esattamente come prima (true/false).
//   - revokedGeneration: SE questa chiamata ha bruciato una generazione,
//     quale generazione è stata bruciata. Se non è avvenuto alcun burn,
//     vale 0 — ma NON bisogna fidarsi di questo valore da solo per
//     capire se un burn è avvenuto, perché 0 è anche un numero di
//     generazione legittimo (il bootstrap parte da g=0): per questo c'è
//     il terzo valore di ritorno.
//   - wasRevoked: flag esplicito e inequivocabile "in QUESTA chiamata è
//     stata bruciata una generazione, sì o no". Elimina l'ambiguità del
//     punto precedente.
//
// Il suffisso "Locked" nel nome segue la stessa convenzione già usata per
// burnLocked/isBurnedLocked: segnala che questa funzione acquisisce v.mu
// per la propria intera durata (fa lei stessa Lock/Unlock, il chiamante
// non deve preoccuparsene) — non va MAI chiamata da un punto che detiene
// già v.mu, altrimenti si va in deadlock per lo stesso motivo spiegato
// sopra.
func (v *Verifier) verifyQuoteLocked(instanceID string, quote model.QuotePayload, expectedNonce []byte) (ok bool, revokedGeneration int, wasRevoked bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	reg, exists := v.registrations[instanceID]
	if !exists {
		return false, 0, false // istanza mai onboardata: niente da bruciare, solo un "no"
	}

	if v.isBurnedLocked(instanceID, quote.Generation) {
		// Generazione già bruciata IN PASSATO da una chiamata precedente:
		// non è un evento NUOVO, quindi non richiede una NUOVA notifica
		// (l'Enforcement è già stato avvisato la prima volta che è
		// successo). wasRevoked resta false apposta.
		return false, 0, false
	}

	// 1. Corrispondenza nonce con la challenge pendente.
	pending, hasPending := v.pendingNonces[instanceID]
	if !hasPending || !bytes.Equal(pending, expectedNonce) || !bytes.Equal(quote.Nonce, expectedNonce) {
		v.burnLocked(instanceID, quote.Generation, "nonce non corrispondente alla challenge pendente")
		// Da qui in avanti, ogni ramo di fallimento che chiama
		// burnLocked restituisce anche (quote.Generation, true): è
		// esattamente il dato che "risale" fuori dal lock fino a
		// VerifyQuote, che lo userà per decidere se avvisare l'Enforcement.
		return false, quote.Generation, true
	}

	// 2. Anti-replay applicativo.
	nonceKey := hex.EncodeToString(quote.Nonce)
	if v.usedNonces[nonceKey] {
		v.burnLocked(instanceID, quote.Generation, "replay attack: nonce già consumato")
		return false, quote.Generation, true
	}

	// 3. Deserializza l'Attestation e delega a server.VerifyAttestation
	// la verifica crittografica TPM-standard.
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(quote.AttestationBlob, &attestation); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("attestation blob non decodificabile: %v", err))
		return false, quote.Generation, true
	}

	if _, err := tpmtoolsserver.VerifyAttestation(&attestation, tpmtoolsserver.VerifyOpts{
		Nonce:      expectedNonce,
		TrustedAKs: []crypto.PublicKey{reg.AKPublicKey},
	}); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("verifica TPM fallita: %v", err))
		return false, quote.Generation, true
	}

	// 4. Confronto del digest PCR con il Golden Measurement di riferimento,
	// estratto direttamente dal TPMS_ATTEST (vedi commento su
	// "registration" più sopra per il perché non usiamo MachineState).
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
		return false, quote.Generation, true
	}
	if !bytes.Equal(actualDigest, reg.GoldenPCRDigest) {
		v.burnLocked(instanceID, quote.Generation, "mismatch PCR rispetto al Golden Measurement")
		return false, quote.Generation, true
	}

	// 5. Generation Exclusivity & Monotonicity.
	if entry, existsLive := v.live[instanceID]; existsLive && quote.Generation < entry.Generation {
		v.burnLocked(instanceID, quote.Generation, "violazione di monotonicità: generazione inferiore a quella live")
		return false, quote.Generation, true
	}

	// Successo: nessun burn avvenuto, nulla da notificare.
	v.usedNonces[nonceKey] = true
	return true, 0, false
}

// OnRevoke registra un hook (una funzione salvata per essere richiamata
// più tardi — vedi il commento in cima al file per l'analogia con
// addActionListener/Consumer) da eseguire ogni volta che il Verifier
// invalida permanentemente una generazione, sia per fallimento di verifica
// (dentro verifyQuoteLocked) sia per una Revoke() manuale (vedi sotto).
//
// Questo metodo si limita ad accodare la funzione in uno slice: non
// acquisisce v.mu. È corretto perché, in questo prototipo, gli hook si
// registrano una volta sola in fase di setup (in main.go, PRIMA che parta
// qualunque verifica) — non c'è quindi concorrenza reale su questo slice
// da proteggere. In un sistema dove le registrazioni potessero avvenire a
// runtime mentre le verifiche sono già in corso, andrebbe protetto da un
// proprio mutex dedicato (non v.mu, per non introdurre esattamente il
// problema di lock-rientranza che stiamo evitando).
func (v *Verifier) OnRevoke(hook func(instanceID string, generation int)) {
	v.onRevoke = append(v.onRevoke, hook)
}

// fireRevokeHooks esegue tutti gli hook registrati, uno dopo l'altro.
//
// REGOLA FERREA su questa funzione: va chiamata SEMPRE E SOLO quando v.mu
// è già stato rilasciato. Per questo il suo nome NON ha il suffisso
// "Locked" (al contrario di burnLocked/isBurnedLocked): è un promemoria
// visivo intenzionale — le funzioni con "Locked" nel nome vanno chiamate
// mentre il lock è acquisito, questa va chiamata quando NON lo è. I due
// punti in cui viene invocata in questo file (VerifyQuote e Revoke, sotto)
// lo fanno correttamente, entrambi dopo che la rispettiva sezione protetta
// da v.mu è già terminata.
func (v *Verifier) fireRevokeHooks(instanceID string, generation int) {
	for _, hook := range v.onRevoke {
		hook(instanceID, generation)
	}
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

// Revoke esegue una revoca MANUALE (es. decisa da un operatore o da una
// policy esterna, non da un fallimento di verifica). Segue lo STESSO
// pattern di VerifyQuote sopra: la parte che tocca lo stato interno
// protetto da v.mu resta isolata in revokeLocked, mentre la notifica agli
// hook (fireRevokeHooks) avviene qui, DOPO che revokeLocked è già tornata
// — quindi a lock sicuramente rilasciato.
func (v *Verifier) Revoke(instanceID string, generation int, reason string) {
	v.revokeLocked(instanceID, generation, reason)
	v.fireRevokeHooks(instanceID, generation)
}

// revokeLocked contiene la sola sezione critica: acquisisce v.mu, marca
// la generazione come bruciata tramite burnLocked, rilascia v.mu (via
// defer). Nessuna notifica avviene qui dentro.
func (v *Verifier) revokeLocked(instanceID string, generation int, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.burnLocked(instanceID, generation, reason)
}

// burnLocked, isBurnedLocked, BurnRecords: INVARIATI rispetto alla
// revisione precedente — pura gestione dello stato interno (mappe), zero
// dipendenze dalla tecnologia di attestazione. burnLocked in particolare
// NON chiama mai fireRevokeHooks direttamente: si limita a registrare il
// BurnRecord e a ripulire lo stato live/pendingNonces, esattamente come
// prima. È deliberatamente "cieco" rispetto agli hook — la responsabilità
// di notificarli, a lock rilasciato, spetta sempre e solo ai chiamanti di
// più alto livello (VerifyQuote, Revoke), mai a questa funzione.
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
