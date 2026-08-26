// Package agent implementa l'Attestation Agent ($A$): un componente a
// fiducia minima che interfaccia il Root of Trust per produrre evidenza
// firmata. L'Agent NON possiede autorità di firma propria "di business":
// la chiave usata è vincolata al TPM e serve solo ad attestare lo stato di
// misurazione, non a concedere fiducia.
//
// CAMBIO RISPETTO ALLA FASE 1: questo file non importa più crypto/rsa né
// alcuna libreria TPM concreta. Dipende esclusivamente dall'interfaccia
// rot.RootOfTrust — è la separazione "logica di business" / "tecnologia
// di attestazione" discussa nella tua domanda: qualunque cosa implementi
// quell'interfaccia (TPM reale, simulatore, in futuro anche un secure
// element diverso) fa funzionare l'Agent senza modifiche a questo file.
package agent

import (
	"google.golang.org/protobuf/proto"

	"ra5g/model"
	"ra5g/rot"
)

// Agent rappresenta l'Attestation Agent locale al Prover.
type Agent struct {
	InstanceID  string
	RoT         rot.RootOfTrust // interfaccia: nessun dettaglio implementativo TPM qui
	Generation  int             // generazione logica corrente, gestita dal chiamante (main.go/Orchestrator)
}

// NewAgent crea un nuovo Agent che si appoggia al RootOfTrust fornito. Il
// RootOfTrust va creato ed eventualmente aperto (simulatore o device
// reale) dal chiamante — l'Agent non decide MAI da solo come connettersi
// al TPM: quella è una decisione di deployment (main.go/orchestrazione),
// non di logica di attestazione.
func NewAgent(instanceID string, root rot.RootOfTrust) *Agent {
	return &Agent{
		InstanceID: instanceID,
		RoT:        root,
	}
}

// ExtendPCR delega l'estensione del registro PCR al RootOfTrust
// sottostante (TPM reale o simulato). A differenza della Fase 1, l'hash
// non è calcolato qui in software: lo calcola il TPM stesso su TPM2_PCR_Event.
func (a *Agent) ExtendPCR(pcrIndex int, event []byte) error {
	return a.RoT.ExtendPCR(pcrIndex, event)
}

// GetTPMQuote produce l'evidenza di attestazione completa (quote TPM
// standard + event log) per i PCR selezionati, legata al nonce del
// Verifier E al contesto dell'operazione (tag: bootstrap, rinnovo,
// migrazione...). Il tipo di ritorno resta model.QuotePayload — la busta
// del NOSTRO protocollo applicativo — ma il suo contenuto crittografico
// ora è prodotto e firmato realmente dal TPM tramite a.RoT.Attest, non
// più simulato in RAM.
//
// AGGIORNAMENTO (context-binding del nonce): invece di passare il nonce
// "nudo" al TPM come ExtraData, calcoliamo prima model.ContextBoundNonce
// — un digest che lega insieme tag, instanceID, generation e nonce — e
// facciamo firmare QUELLO al TPM. Il campo QuotePayload.Nonce continua a
// contenere il nonce originale "in chiaro" (serve al Verifier per il
// proprio bookkeeping anti-replay, invariato rispetto a prima); è solo
// ciò che viene effettivamente dato in pasto al TPM a essere cambiato.
func (a *Agent) GetTPMQuote(generation int, nonce []byte, pcrSelection []int, tag model.ContextTag) (*model.QuotePayload, error) {
	boundNonce := model.ContextBoundNonce(tag, a.InstanceID, generation, nonce)

	attestation, err := a.RoT.Attest(pcrSelection, boundNonce)
	if err != nil {
		return nil, err
	}

	// Serializziamo il messaggio Attestation prodotto dal RoT in bytes
	// grezzi (Protobuf), da trasportare così com'è nel payload applicativo.
	// In Fase 1 sarebbe stato del tutto naturale immaginare che, quando si
	// introdurrà il livello di trasporto gRPC (vedi documento originale,
	// punto 2.2), il messaggio Attestation verrà serializzato/deserializzato
	// automaticamente dallo stub gRPC: qui lo facciamo esplicitamente per
	// restare, come richiesto, "pacchetti Go puri" senza infrastruttura di
	// rete, testabili in-process.
	blob, err := marshalAttestation(attestation)
	if err != nil {
		return nil, err
	}

	return &model.QuotePayload{
		InstanceID:      a.InstanceID,
		Generation:      generation,
		Tag:             tag,
		Nonce:           nonce,
		AttestationBlob: blob,
	}, nil
}

// GetMigrationSourceQuote produce la quote dell'istanza USCENTE durante
// una migrazione (Fase 3): equivalente concettuale di GetTPMQuote, ma usa
// model.MigrationSourceBoundNonce invece di model.ContextBoundNonce,
// perché in questo caso il TPM deve firmare anche l'host di destinazione
// (targetHost), non solo tag/instanceID/generation/nonce — vedi il
// commento su MigrationSourceBoundNonce in model/types.go per il perché.
//
// Il campo QuotePayload.Generation contiene la generazione CORRENTE
// (g_0, quella da cui si sta migrando via), non quella nuova: è coerente
// con "questa è la prova che l'istanza ATTUALMENTE alla generazione g_0
// acconsente alla migrazione", non una dichiarazione sulla nuova
// generazione (che non esiste ancora finché l'istanza target non avrà
// prodotto la propria quote — vedi CompleteMigration in verifier.go).
func (a *Agent) GetMigrationSourceQuote(oldGeneration int, nonce []byte, pcrSelection []int, targetHost string) (*model.QuotePayload, error) {
	boundNonce := model.MigrationSourceBoundNonce(a.InstanceID, oldGeneration, nonce, targetHost)

	attestation, err := a.RoT.Attest(pcrSelection, boundNonce)
	if err != nil {
		return nil, err
	}

	blob, err := marshalAttestation(attestation)
	if err != nil {
		return nil, err
	}

	return &model.QuotePayload{
		InstanceID:      a.InstanceID,
		Generation:      oldGeneration,
		Tag:             model.ContextTagMigrate,
		Nonce:           nonce,
		TargetHost:      targetHost,
		AttestationBlob: blob,
	}, nil
}

// marshalAttestation serializza in Protobuf wire-format il messaggio
// Attestation restituito dal RootOfTrust. Accetta proto.Message (interfaccia
// generica della libreria protobuf standard, NON specifica di go-tpm-tools)
// così che questo file non debba importare il tipo concreto attestpb.Attestation:
// resta legato solo al CONTRATTO "è un messaggio protobuf", coerente con
// l'obiettivo di isolare le dipendenze TPM-specifiche nel package rot.
func marshalAttestation(msg proto.Message) ([]byte, error) {
	return proto.Marshal(msg)
}
