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

// DefaultMigrationTTL è la validità massima di una migrazione avviata
// con BeginMigration ma non ancora portata a termine con
// CompleteMigration. Risolve una lacuna nota (segnalata in
// docs/05-roadmap.md): senza un TTL, una migrazione avviata e poi mai
// completata — perché l'host target non risponde più, l'Orchestrator si
// blocca, o semplicemente nessuno richiama mai CompleteMigration —
// lasciava lo stato interno del Verifier "appeso" indefinitamente per
// quella istanza, un piccolo ma reale leak di memoria/stato.
//
// Il valore è più permissivo di DefaultTokenTTL (30s) perché una
// migrazione reale comporta passi aggiuntivi rispetto a un semplice
// rinnovo — l'Orchestrator deve istanziare il pod sull'host target, il
// nuovo TPM deve produrre la propria quote — che possono richiedere più
// tempo di un banale round-trip di attestazione. È comunque un valore
// arbitrario per questo prototipo: in un deployment reale andrebbe
// calibrato sui tempi di provisioning tipici dell'infrastruttura.
const DefaultMigrationTTL = 2 * time.Minute

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

	// pendingMigrations tiene traccia, per istanza, di una migrazione
	// avviata ma non ancora completata (Fase 3). È uno stato SEPARATO da
	// pendingNonces/usedNonces (usati per Bootstrap/Renew) perché la
	// migrazione coinvolge DUE quote correlate dallo STESSO nonce n_mig
	// (Q_src e Q_dst) — un modello "una challenge, una risposta" come
	// quello di pendingNonces non si adatta a questo schema senza
	// forzature. Tenerli separati evita che la logica di un meccanismo
	// interferisca con l'altro.
	pendingMigrations map[string]*migrationState

	// onRevoke contiene gli "hook" (funzioni salvate per essere richiamate
	// più tardi, non chiamate qui) da eseguire ogni volta che il Verifier
	// invalida permanentemente una generazione. Il pattern completo è
	// spiegato nel commento sopra fireRevokeHooks più sotto — qui basti
	// sapere che si tratta di un semplice slice di funzioni, popolato in
	// fase di setup da main.go tramite OnRevoke(), MAI durante la verifica
	// vera e propria.
	onRevoke []func(instanceID string, generation int)
}

// migrationState rappresenta una migrazione in corso per una singola
// istanza, tra l'emissione della challenge (BeginMigration) e il suo
// esito finale (CompleteMigration, con successo o abort).
type migrationState struct {
	Nonce         []byte
	TargetHost    string
	OldGeneration int

	// ExpiresAt impostato da BeginMigration a now+DefaultMigrationTTL: se
	// né ValidateMigrationSource né CompleteMigration riescono a portare
	// a termine la migrazione entro questo termine, lo stato pendente
	// viene ripulito automaticamente alla PROSSIMA chiamata che lo tocca
	// (stessa strategia "lazy", non un timer/goroutine di background, già
	// usata per la scadenza dei Token in Enforcement.IsRoutingAllowed —
	// coerente con lo stile del resto del progetto).
	ExpiresAt time.Time

	// SourceValidated diventa true solo dopo che ValidateMigrationSource
	// ha verificato con successo Q_src. CompleteMigration RIFIUTA di
	// procedere se questo campo è ancora false: è la parte "atomica" del
	// commit — la nuova generazione non viene MAI ammessa senza che
	// l'istanza uscente abbia prima acconsentito esplicitamente.
	SourceValidated bool
}

// isMigrationExpiredLocked verifica se una migrazione pendente ha
// superato il proprio ExpiresAt. Come le altre funzioni con suffisso
// "Locked", assume che v.mu sia già acquisito dal chiamante.
func isMigrationExpiredLocked(pending *migrationState) bool {
	return time.Now().After(pending.ExpiresAt)
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
		privKey:           priv,
		pubKey:            &priv.PublicKey,
		registrations:     make(map[string]registration),
		live:              make(map[string]*liveEntry),
		pendingNonces:     make(map[string][]byte),
		usedNonces:        make(map[string]bool),
		burnRecords:       make(map[string][]model.BurnRecord),
		pendingMigrations: make(map[string]*migrationState),
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
func (v *Verifier) VerifyQuote(instanceID string, quote model.QuotePayload, expectedNonce []byte, expectedTag model.ContextTag) bool {
	// verifyQuoteLocked "fa risalire" fuori dal lock l'informazione su
	// COSA è successo, non solo SE la verifica è riuscita: da qui in poi
	// possiamo decidere se notificare gli hook, con la certezza che il
	// lock del Verifier (v.mu) è già stato rilasciato (il suo
	// "defer v.mu.Unlock()" interno è scattato non appena la funzione è
	// tornata, PRIMA che l'esecuzione arrivi a questa riga).
	ok, revokedGeneration, wasRevoked := v.verifyQuoteLocked(instanceID, quote, expectedNonce, expectedTag)

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
func (v *Verifier) verifyQuoteLocked(instanceID string, quote model.QuotePayload, expectedNonce []byte, expectedTag model.ContextTag) (ok bool, revokedGeneration int, wasRevoked bool) {
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

	// 1. Corrispondenza del CONTEXT TAG con quello atteso per questa
	// specifica challenge. Un Verifier che ha emesso una challenge per un
	// rinnovo (ContextTagRenew) non deve MAI accettare come risposta una
	// quote marcata come bootstrap o migrazione, anche se nonce e firma
	// fossero altrimenti perfettamente validi — è il controllo che
	// impedisce di riutilizzare una quote legittima FUORI dal contesto
	// per cui è stata prodotta.
	if quote.Tag != expectedTag {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("context tag non corrispondente: atteso %q, ricevuto %q", expectedTag, quote.Tag))
		return false, quote.Generation, true
	}

	// 2. Corrispondenza nonce con la challenge pendente.
	pending, hasPending := v.pendingNonces[instanceID]
	if !hasPending || !bytes.Equal(pending, expectedNonce) || !bytes.Equal(quote.Nonce, expectedNonce) {
		v.burnLocked(instanceID, quote.Generation, "nonce non corrispondente alla challenge pendente")
		// Da qui in avanti, ogni ramo di fallimento che chiama
		// burnLocked restituisce anche (quote.Generation, true): è
		// esattamente il dato che "risale" fuori dal lock fino a
		// VerifyQuote, che lo userà per decidere se avvisare l'Enforcement.
		return false, quote.Generation, true
	}

	// 3. Anti-replay applicativo.
	nonceKey := hex.EncodeToString(quote.Nonce)
	if v.usedNonces[nonceKey] {
		v.burnLocked(instanceID, quote.Generation, "replay attack: nonce già consumato")
		return false, quote.Generation, true
	}

	// 4. Deserializza l'Attestation e delega a server.VerifyAttestation
	// la verifica crittografica TPM-standard.
	var attestation attestpb.Attestation
	if err := proto.Unmarshal(quote.AttestationBlob, &attestation); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("attestation blob non decodificabile: %v", err))
		return false, quote.Generation, true
	}

	// AGGIORNAMENTO (context-binding del nonce): non passiamo più
	// expectedNonce "nudo" a VerifyAttestation, ma il suo equivalente
	// vincolato al contesto — ESATTAMENTE lo stesso valore che l'Agent ha
	// calcolato (con model.ContextBoundNonce) prima di farlo firmare dal
	// TPM in agent.go. Se un attaccante avesse rigiocato una quote
	// prodotta per un tag diverso, questo confronto fallirebbe anche
	// qualora il controllo al punto 1 fosse stato in qualche modo aggirato
	// — due strati di difesa indipendenti sullo stesso problema.
	boundNonce := model.ContextBoundNonce(quote.Tag, instanceID, quote.Generation, expectedNonce)
	if _, err := tpmtoolsserver.VerifyAttestation(&attestation, tpmtoolsserver.VerifyOpts{
		Nonce:      boundNonce,
		TrustedAKs: []crypto.PublicKey{reg.AKPublicKey},
	}); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("verifica TPM fallita: %v", err))
		return false, quote.Generation, true
	}

	// 5. Confronto del digest PCR con il Golden Measurement di riferimento,
	// estratto direttamente dal TPMS_ATTEST (vedi commento su
	// "registration" più sopra per il perché non usiamo MachineState).
	//
	// AGGIORNAMENTO (Fase 3): questa estrazione è ora condivisa con
	// validateMigrationSourceLocked/CompleteMigration tramite la funzione
	// extractSHA256PCRDigest più sotto — la stessa logica serviva
	// identica in più punti, e duplicarla avrebbe rischiato un
	// disallineamento silenzioso tra le due copie in futuro.
	actualDigest, foundDigest := extractSHA256PCRDigest(&attestation)
	if !foundDigest {
		v.burnLocked(instanceID, quote.Generation, "nessuna quote SHA-256 valida trovata nell'attestazione")
		return false, quote.Generation, true
	}
	if !bytes.Equal(actualDigest, reg.GoldenPCRDigest) {
		v.burnLocked(instanceID, quote.Generation, "mismatch PCR rispetto al Golden Measurement")
		return false, quote.Generation, true
	}

	// 6. Generation Exclusivity & Monotonicity.
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
	return v.issueTokenLocked(instanceID, generation)
}

// issueTokenLocked contiene il corpo effettivo di IssueToken, INVARIATO
// rispetto a prima, ma estratto in una funzione a sé che ASSUME v.mu già
// acquisito dal chiamante (da qui il suffisso "Locked", stessa convenzione
// di burnLocked/isBurnedLocked).
//
// PERCHÉ QUESTA ESTRAZIONE SERVE (Fase 3): CompleteMigration deve
// eseguire "Retract Live(g_0) + Assert Live(g_1) + emetti Token" come
// un'UNICA operazione atomica, sotto un solo Lock/Unlock — se
// CompleteMigration chiamasse il vecchio IssueToken (che fa il proprio
// Lock/Unlock indipendente), si spezzerebbe l'atomicità (esisterebbe un
// istante, tra l'aggiornamento di v.live e l'emissione del token, in cui
// un'altra goroutine potrebbe osservare uno stato intermedio) — e, più
// gravemente, se CompleteMigration detenesse già v.mu quando chiamasse
// IssueToken, andrebbe in deadlock (stesso problema di sync.Mutex non
// rientrante già discusso per gli hook di revoca).
func (v *Verifier) issueTokenLocked(instanceID string, generation int) (*model.Token, error) {
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

// extractSHA256PCRDigest estrae il PCRDigest dal TPMS_ATTEST incapsulato
// nella prima quote, tra quelle presenti in attestation.GetQuotes(), che
// risulti sul banco SHA-256. Condivisa tra verifyQuoteLocked (Bootstrap/
// Renew) e validateMigrationSourceLocked/CompleteMigration (Fase 3): è
// esattamente la stessa operazione, indipendentemente dal contesto in
// cui la quote è stata prodotta.
func extractSHA256PCRDigest(attestation *attestpb.Attestation) ([]byte, bool) {
	for _, q := range attestation.GetQuotes() {
		ad, decodeErr := tpm2.DecodeAttestationData(q.GetQuote())
		if decodeErr != nil || ad.AttestedQuoteInfo == nil {
			continue
		}
		if ad.AttestedQuoteInfo.PCRSelection.Hash == tpm2.AlgSHA256 {
			return ad.AttestedQuoteInfo.PCRDigest, true
		}
	}
	return nil, false
}

// ============================================================================
// FASE 3 — Migrazione Cooperativa
// ============================================================================
//
// I tre metodi seguenti implementano il flusso descritto dal sequence
// diagram del protocollo: BeginMigration (challenge), ValidateMigrationSource
// (Q_src, dall'istanza uscente), CompleteMigration (Q_dst dall'istanza
// entrante + Atomic Commit). A differenza di VerifyQuote, che gestisce
// Bootstrap e Renew con la STESSA funzione (perché sono, dal punto di
// vista del Verifier, la stessa operazione ripetuta), la migrazione
// richiede tre funzioni distinte perché coinvolge DUE parti (istanza
// uscente ed entrante) che il Verifier deve coordinare, non una singola
// challenge/risposta.

// BeginMigration avvia una richiesta di migrazione cooperativa per
// l'istanza indicata verso targetHost — corrisponde al messaggio
// "Challenge Migrazione (nonce n_mig)" del sequence diagram, emesso in
// risposta a un MigrateRequest innescato dall'Orchestrator. Coerentemente
// con "Orchestrator Non-Authority" (proprietà di sicurezza già discussa
// nel resto del progetto): il trigger dell'Orchestrator non concede
// alcuna fiducia da solo, si limita a far generare al Verifier una nuova
// challenge — tutta la fiducia verrà concessa solo più avanti, e solo a
// fronte di evidenza TPM firmata da ENTRAMBE le istanze coinvolte.
func (v *Verifier) BeginMigration(instanceID string, targetHost string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	entry, ok := v.live[instanceID]
	if !ok {
		return nil, fmt.Errorf("verifier: impossibile avviare una migrazione per %q: nessuna generazione attualmente live", instanceID)
	}

	nonce, err := cryptoutil.NewNonce(32)
	if err != nil {
		return nil, err
	}

	v.pendingMigrations[instanceID] = &migrationState{
		Nonce:         nonce,
		TargetHost:    targetHost,
		OldGeneration: entry.Generation,
		ExpiresAt:     time.Now().Add(DefaultMigrationTTL),
	}

	return nonce, nil
}

// ValidateMigrationSource verifica Q_src, la quote con cui l'istanza
// USCENTE acconsente alla migrazione (prodotta da
// agent.GetMigrationSourceQuote).
//
// SCELTA DI SICUREZZA DELIBERATA: a differenza di CompleteMigration (vedi
// sotto), un fallimento QUI brucia la generazione corrente. La
// motivazione: questa quote proviene dall'istanza CHE STA ATTUALMENTE
// SERVENDO TRAFFICO. Se non riesce a produrre una prova valida di sé
// stessa — che si tratti di un nonce sbagliato, un mismatch PCR, o una
// firma non valida — è un segnale d'allarme sulla stessa generazione
// live, non un semplice "problema con la richiesta di migrazione": è
// esattamente lo stesso tipo di evento che VerifyQuote tratterebbe come
// un'anomalia da mettere in quarantena (Fase 4 del documento di analisi).
func (v *Verifier) ValidateMigrationSource(instanceID string, quote model.QuotePayload) bool {
	ok, revokedGeneration, wasRevoked := v.validateMigrationSourceLocked(instanceID, quote)

	// Stesso pattern già discusso per VerifyQuote: gli hook di revoca
	// vengono notificati SOLO dopo che validateMigrationSourceLocked è
	// già tornata, quindi con v.mu sicuramente rilasciato.
	if wasRevoked {
		v.fireRevokeHooks(instanceID, revokedGeneration)
	}

	return ok
}

func (v *Verifier) validateMigrationSourceLocked(instanceID string, quote model.QuotePayload) (ok bool, revokedGeneration int, wasRevoked bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	reg, exists := v.registrations[instanceID]
	if !exists {
		return false, 0, false
	}

	pending, hasPending := v.pendingMigrations[instanceID]
	if !hasPending {
		// Nessuna migrazione avviata per questa istanza tramite
		// BeginMigration: potrebbe essere una chiamata semplicemente
		// fuori sequenza (non necessariamente un attacco), quindi non
		// bruciamo nulla — ci limitiamo a rifiutare.
		return false, 0, false
	}

	if isMigrationExpiredLocked(pending) {
		// La migrazione era stata avviata, ma nessuno ha portato Q_src
		// entro DefaultMigrationTTL: NON è di per sé un evento sospetto
		// (può capitare per un ritardo di rete o un Orchestrator lento),
		// quindi — a differenza dei rami sotto — non brucia nulla: si
		// limita a ripulire lo stato pendente scaduto, esattamente come
		// se la migrazione non fosse mai stata avviata. Un nuovo tentativo
		// dovrà ripartire da una BeginMigration.
		delete(v.pendingMigrations, instanceID)
		return false, 0, false
	}

	if v.isBurnedLocked(instanceID, quote.Generation) {
		return false, 0, false
	}

	if quote.Tag != model.ContextTagMigrate {
		v.burnLocked(instanceID, quote.Generation, "Q_src: context tag non corrispondente, attesa una quote di migrazione")
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}
	if quote.Generation != pending.OldGeneration {
		v.burnLocked(instanceID, quote.Generation, "Q_src: generazione diversa da quella live al momento della richiesta di migrazione")
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}
	if quote.TargetHost != pending.TargetHost {
		v.burnLocked(instanceID, quote.Generation, "Q_src: host di destinazione diverso da quello della migrazione avviata")
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}
	if !bytes.Equal(quote.Nonce, pending.Nonce) {
		v.burnLocked(instanceID, quote.Generation, "Q_src: nonce non corrispondente alla challenge di migrazione")
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}

	var attestation attestpb.Attestation
	if err := proto.Unmarshal(quote.AttestationBlob, &attestation); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("Q_src: attestation blob non decodificabile: %v", err))
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}

	// Ricalcola lo stesso valore che agent.GetMigrationSourceQuote ha
	// fatto firmare al TPM: tag Migrate implicito, generazione USCENTE,
	// nonce di migrazione, host di destinazione.
	boundNonce := model.MigrationSourceBoundNonce(instanceID, quote.Generation, pending.Nonce, pending.TargetHost)
	if _, err := tpmtoolsserver.VerifyAttestation(&attestation, tpmtoolsserver.VerifyOpts{
		Nonce:      boundNonce,
		TrustedAKs: []crypto.PublicKey{reg.AKPublicKey},
	}); err != nil {
		v.burnLocked(instanceID, quote.Generation, fmt.Sprintf("Q_src: verifica TPM fallita: %v", err))
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}

	actualDigest, foundDigest := extractSHA256PCRDigest(&attestation)
	if !foundDigest || !bytes.Equal(actualDigest, reg.GoldenPCRDigest) {
		v.burnLocked(instanceID, quote.Generation, "Q_src: mismatch PCR rispetto al Golden Measurement")
		delete(v.pendingMigrations, instanceID)
		return false, quote.Generation, true
	}

	// Successo: marca la migrazione pendente come "lato sorgente
	// validato". NON viene bruciato nulla, NON viene toccato v.live —
	// quella parte avviene solo nell'Atomic Commit di CompleteMigration,
	// e solo se anche Q_dst risulterà valida.
	pending.SourceValidated = true
	return true, 0, false
}

// CompleteMigration verifica Q_dst (la quote dell'istanza ENTRANTE
// sull'host target) e, solo se ANCHE Q_src era già stata validata da
// ValidateMigrationSource, esegue l'Atomic Commit descritto dal sequence
// diagram in un'UNICA sezione critica (un solo Lock/Unlock): aggiorna la
// registrazione dell'istanza con la AK e il Golden Measurement del nuovo
// host, ritira implicitamente g_0 e ammette g_1 (sovrascrivendo
// v.live[instanceID] in un solo passaggio — non esiste alcun istante
// intermedio in cui l'istanza risulti live su entrambe le generazioni),
// emette un nuovo Token per g_1 e un GenerationLinkCert firmato che lega
// le due generazioni.
//
// newAKPublicKey/newGoldenPCRDigest rappresentano l'onboarding dell'host
// target: in questo prototipo vengono passati direttamente dal
// chiamante (main.go, che li ottiene fuori banda dall'Agent target) —
// esattamente lo stesso limite già documentato per RegisterInstance
// (nessuna certificazione EK→AK ancora implementata, vedi docs/05-roadmap.md).
//
// SCELTA DI SICUREZZA DELIBERATA (complementare a ValidateMigrationSource):
// un fallimento QUI NON brucia alcuna generazione. Q_src era già stata
// validata con successo — l'istanza sorgente ha provato sé stessa
// correttamente. Un problema sul lato TARGET (rete instabile, TPM del
// nuovo host non ancora pronto, mismatch PCR sull'immagine di
// destinazione...) non implica che la sorgente sia compromessa: la
// migrazione viene semplicemente abortita, g_0 resta live e continua a
// servire traffico normalmente, senza alcuna conseguenza per essa.
func (v *Verifier) CompleteMigration(instanceID string, newGeneration int, dstQuote model.QuotePayload, newAKPublicKey crypto.PublicKey, newGoldenPCRDigest []byte) (*model.Token, *model.GenerationLinkCert, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	pending, hasPending := v.pendingMigrations[instanceID]
	if !hasPending {
		return nil, nil, false
	}

	if isMigrationExpiredLocked(pending) {
		// Stesso ragionamento di validateMigrationSourceLocked: una
		// migrazione scaduta (Q_dst mai arrivata entro
		// DefaultMigrationTTL, magari perché ValidateMigrationSource era
		// già avvenuta ma poi l'host target non ha mai risposto) non è
		// di per sé un'anomalia da punire — si ripulisce lo stato
		// pendente e si rifiuta, senza intaccare in alcun modo la
		// generazione sorgente (che può essere ancora perfettamente
		// valida e servire traffico).
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}

	if !pending.SourceValidated {
		// Violazione della proprietà "Atomic Migration (Dual-Sided
		// Authorization)" del documento di analisi originale: senza un
		// Q_src già validato, non esiste alcun consenso accertato
		// dell'istanza uscente — CompleteMigration si rifiuta di
		// procedere, qualunque sia il contenuto di dstQuote. Non ripulisce
		// lo stato pendente: la migrazione resta aperta in attesa che
		// ValidateMigrationSource venga chiamata (l'ordine con cui Q_src e
		// Q_dst arrivano non è garantito dal trasporto).
		return nil, nil, false
	}

	if dstQuote.Tag != model.ContextTagMigrate {
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}
	if !bytes.Equal(dstQuote.Nonce, pending.Nonce) {
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}
	if newGeneration <= pending.OldGeneration {
		// La migrazione deve SEMPRE produrre una generazione strettamente
		// maggiore di quella uscente — a differenza di un rinnovo (dove
		// la stessa generazione è legittima), qui si sta affermando
		// l'esistenza di un'istanza fisicamente diversa.
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}
	if v.isBurnedLocked(instanceID, newGeneration) {
		// Controllo difensivo eseguito PRIMA di qualunque mutazione di
		// stato (vedi sotto): garantisce che, se dovesse mai fallire,
		// nessuna scrittura parziale sia già avvenuta — l'Atomic Commit
		// resta "tutto o niente" anche in questo caso limite.
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}

	var attestation attestpb.Attestation
	if err := proto.Unmarshal(dstQuote.AttestationBlob, &attestation); err != nil {
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}

	// La quote dell'istanza ENTRANTE usa ContextBoundNonce, la versione
	// GENERICA (non MigrationSourceBoundNonce): l'istanza target non sta
	// "acconsentendo a migrare verso un host" — è già lì fisicamente —
	// sta solo attestando sé stessa in una nuova generazione, esattamente
	// come farebbe in un Bootstrap ordinario, con tag Migrate al posto
	// di Boot.
	boundNonce := model.ContextBoundNonce(model.ContextTagMigrate, instanceID, newGeneration, pending.Nonce)
	if _, err := tpmtoolsserver.VerifyAttestation(&attestation, tpmtoolsserver.VerifyOpts{
		Nonce:      boundNonce,
		TrustedAKs: []crypto.PublicKey{newAKPublicKey},
	}); err != nil {
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}

	actualDigest, foundDigest := extractSHA256PCRDigest(&attestation)
	if !foundDigest || !bytes.Equal(actualDigest, newGoldenPCRDigest) {
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}

	// --- ATOMIC COMMIT ---
	// Da qui in avanti nessun controllo può più fallire (tutte le
	// verifiche sono già state completate sopra): quanto segue è pura
	// applicazione dello stato, non validazione.

	// 1. Da questo momento l'istanza attesta sé stessa dal TPM del nuovo
	// host: la registrazione viene aggiornata con la nuova AK e il nuovo
	// Golden Measurement (l'immagine software sul target potrebbe
	// legittimamente differire, es. per un aggiornamento contestuale
	// alla migrazione).
	v.registrations[instanceID] = registration{
		AKPublicKey:     newAKPublicKey,
		GoldenPCRDigest: newGoldenPCRDigest,
	}

	// 2/3. Retract Live(g_0) + Assert Live(g_1): issueTokenLocked
	// sovrascrive v.live[instanceID] con la nuova generazione in
	// un'unica scrittura, sotto lo stesso lock già acquisito da questa
	// funzione — l'atomicità è garantita dal fatto che nessun'altra
	// goroutine può osservare lo stato del Verifier finché questa
	// funzione non rilascia v.mu (il defer in cima alla funzione).
	token, err := v.issueTokenLocked(instanceID, newGeneration)
	if err != nil {
		// Ramo difensivo, in pratica irraggiungibile: il controllo
		// isBurnedLocked(instanceID, newGeneration) sopra ha già escluso
		// l'unica condizione che farebbe fallire issueTokenLocked, e
		// nessun'altra goroutine ha potuto modificare lo stato nel
		// frattempo (lock continuamente detenuto).
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}

	cert := &model.GenerationLinkCert{
		InstanceID:    instanceID,
		OldGeneration: pending.OldGeneration,
		NewGeneration: newGeneration,
		MigNonce:      pending.Nonce,
		TargetHost:    pending.TargetHost,
	}
	sig, err := cryptoutil.Sign(v.privKey, cert.SignedBytes())
	if err != nil {
		delete(v.pendingMigrations, instanceID)
		return nil, nil, false
	}
	cert.SignatureV = sig

	delete(v.pendingMigrations, instanceID)
	return token, cert, true
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
