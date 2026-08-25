// Package enforcement implementa l'Enforcement Plane ($E$): il componente
// fidato per l'esecuzione delle regole di instradamento (es. Service Mesh,
// Envoy Proxy, CNI). $E$ non contatta mai direttamente il Prover: agisce
// esclusivamente sulla base di Token firmati emessi dal Verifier.
//
// FASE 2: questo file è IDENTICO alla Fase 1, non modificato. È la prova
// pratica che isolare la logica di business (qui: fail-closed, generation
// exclusivity sui token) dalla tecnologia di attestazione (TPM) funziona:
// passare da una simulazione software a un vero TPM per l'Agent/Verifier
// non ha richiesto toccare l'Enforcement Plane in nessun modo.
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
