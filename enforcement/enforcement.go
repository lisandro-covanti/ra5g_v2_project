// Package enforcement implementa l'Enforcement Plane ($E$): il componente
// fidato per l'esecuzione delle regole di instradamento (es. Service Mesh,
// Envoy Proxy, CNI). $E$ non contatta mai direttamente il Prover: agisce
// esclusivamente sulla base di Token firmati emessi dal Verifier.
//
// AGGIORNAMENTO: rispetto alla prima versione della Fase 2 (dove questo
// file era identico byte-per-byte alla Fase 1), è stato aggiunto un solo
// metodo, Revoke, che apre un canale di notifica diretta dal Verifier
// verso l'Enforcement per la revoca immediata del routing (invece di
// affidarsi solo alla scadenza naturale del token). Tutto il resto del
// file — ValidateToken, UpdateRoutingRules, IsRoutingAllowed, il default
// Fail-Closed — resta invariato.
package enforcement

import (
	"crypto/rsa"
	"sync"
	"time"

	"ra5g/cryptoutil"
	"ra5g/model"
)

// routeState tiene traccia, per singola istanza logica, della generazione
// correntemente ammessa e della scadenza del relativo token.
type routeState struct {
	Generation int
	ExpiresAt  time.Time
	Allowed    bool
}

// Enforcement implementa l'entità $E$.
type Enforcement struct {
	mu sync.Mutex

	verifierPubKey *rsa.PublicKey // pk_V, distribuito fuori banda dal Verifier

	// highestAdmitted traccia, per istanza, la generazione più alta mai
	// ammessa. Serve a far rispettare la Generation Exclusivity: una volta
	// che $E$ instrada verso la generazione N, non instraderà mai più
	// verso una generazione < N per la stessa istanza logica (protezione
	// da rollback / doppio instradamento).
	highestAdmitted map[string]int
	routes          map[string]*routeState
}

// New crea un nuovo Enforcement Plane collegato alla chiave pubblica del
// Verifier (pk_V), necessaria per validare la firma dei token.
func New(verifierPubKey *rsa.PublicKey) *Enforcement {
	return &Enforcement{
		verifierPubKey:  verifierPubKey,
		highestAdmitted: make(map[string]int),
		routes:          make(map[string]*routeState),
	}
}

// ValidateToken verifica: (1) la firma sk_V, (2) la scadenza (ExpiresAt),
// (3) la Generation Exclusivity, ovvero che la generazione del token non
// sia mai inferiore alla generazione più alta già ammessa in precedenza per
// quella istanza. Un token per la STESSA generazione già ammessa è valido
// (rinnovo/continuous attestation); un token per una generazione superiore
// rappresenta una transizione legittima (bootstrap successivo o
// migrazione) e sostituisce atomicamente quella precedente; un token per
// una generazione inferiore viene sempre rifiutato.
func (e *Enforcement) ValidateToken(token *model.Token) bool {
	if token == nil {
		return false
	}

	if !cryptoutil.Verify(e.verifierPubKey, token.SignedBytes(), token.SignatureV) {
		return false
	}

	if time.Now().After(token.ExpiresAt) {
		return false
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if highest, ok := e.highestAdmitted[token.InstanceID]; ok && token.Generation < highest {
		return false // violazione di Generation Exclusivity: mai tornare indietro
	}

	return true
}

// UpdateRoutingRules abilita l'instradamento del traffico verso l'istanza
// SOLO se il token è valido. In caso contrario (token nil, firma non
// valida, scaduto, o generazione non ammissibile) il traffico viene
// immediatamente interrotto: questo è il comportamento Fail-Closed
// richiesto per default in assenza di un token valido.
func (e *Enforcement) UpdateRoutingRules(token *model.Token) {
	if !e.ValidateToken(token) {
		if token != nil {
			e.denyLocked(token.InstanceID)
		}
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Generation Exclusivity: mai instradare simultaneamente verso due
	// generazioni diverse della stessa istanza logica. L'ammissione di una
	// nuova generazione sostituisce atomicamente quella precedente.
	e.highestAdmitted[token.InstanceID] = token.Generation
	e.routes[token.InstanceID] = &routeState{
		Generation: token.Generation,
		ExpiresAt:  token.ExpiresAt,
		Allowed:    true,
	}
}

// denyLocked interrompe l'instradamento verso un'istanza (Fail-Closed).
func (e *Enforcement) denyLocked(instanceID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rs, ok := e.routes[instanceID]; ok {
		rs.Allowed = false
	} else {
		e.routes[instanceID] = &routeState{Allowed: false}
	}
}

// Revoke forza IMMEDIATAMENTE la negazione del routing per una specifica
// coppia (instanceID, generation), SENZA aspettare la scadenza naturale
// del token corrente (ExpiresAt).
//
// PERCHÉ SERVE (gap colmato rispetto alla prima versione di questo file):
// prima d'ora, l'UNICO modo per interrompere il routing era il timeout
// del token (fino a DefaultTokenTTL = 30s dal Verifier). Se il Verifier
// scopriva un replay attack o un mismatch PCR e bruciava la generazione,
// l'Enforcement non veniva MAI avvisato attivamente: continuava a
// instradare il traffico verso l'istanza compromessa finché il token in
// suo possesso non scadeva da solo. Questo metodo è il canale diretto che
// il Verifier chiama (tramite un hook registrato in main.go — vedi
// verifier.go) nell'istante stesso in cui rileva un'anomalia, corrispondente
// al passo "Revoca Immediata Routing" della Fase 4 del sequence diagram.
//
// Chi chiama questo metodo (il Verifier, tramite hook) NON deve MAI farlo
// mentre detiene il proprio lock interno (v.mu) — altrimenti, se in futuro
// questo metodo (o un suo effetto a catena) richiamasse un metodo del
// Verifier che a sua volta prova a riacquisire v.mu, si creerebbe un
// deadlock: una goroutine che aspetta un lock che possiede già lei stessa.
// Questa garanzia è responsabilità del CHIAMANTE (verifier.go: gli hook
// vengono sempre invocati DOPO che il lock del Verifier è stato rilasciato)
// — Enforcement.Revoke di per sé è "innocuo" da questo punto di vista,
// perché usa solo e.mu, un mutex diverso e indipendente da quello del
// Verifier: non può MAI essere lui a causare quel particolare deadlock.
func (e *Enforcement) Revoke(instanceID string, generation int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rs, ok := e.routes[instanceID]
	if !ok {
		// Nessuna regola di routing attiva per questa istanza: non c'è
		// nulla da revocare (può succedere se il Verifier notifica un
		// burn per un'istanza che l'Enforcement non ha ancora mai visto,
		// ad esempio un fallimento già al primissimo Bootstrap, prima
		// che UpdateRoutingRules sia mai stato chiamato con successo).
		return
	}
	if rs.Generation != generation {
		// Guardia contro eventi "in ritardo": se l'istanza è nel
		// frattempo GIÀ passata a una generazione più recente (es. dopo
		// una migrazione riuscita), una notifica di burn arrivata tardi
		// e riferita alla VECCHIA generazione non deve interrompere il
		// routing della generazione ATTUALE, più recente e legittima.
		// Senza questo controllo, un evento ormai obsoleto potrebbe
		// interrompere traffico corretto — è la stessa logica di
		// Generation Exclusivity già applicata altrove in questo file.
		return
	}
	rs.Allowed = false
}

// IsRoutingAllowed è la funzione che il data-plane (Envoy/CNI) invocherebbe
// ad ogni decisione di instradamento. Applica il default Fail-Closed: se
// non esiste alcuna regola per l'istanza, o se il lease è scaduto (anche
// se non è ancora arrivato un nuovo token/lease-expiry event esplicito), il
// traffico NON viene instradato.
func (e *Enforcement) IsRoutingAllowed(instanceID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	rs, ok := e.routes[instanceID]
	if !ok || !rs.Allowed {
		return false
	}
	if time.Now().After(rs.ExpiresAt) {
		rs.Allowed = false // scadenza della lease: richiude immediatamente
		return false
	}
	return true
}
