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
// Verifier. Il tipo di ritorno resta model.QuotePayload — la busta del
// NOSTRO protocollo applicativo — ma il suo contenuto crittografico ora è
// prodotto e firmato realmente dal TPM tramite a.RoT.Attest, non più
// simulato in RAM.
func (a *Agent) GetTPMQuote(generation int, nonce []byte, pcrSelection []int) (*model.QuotePayload, error) {
	attestation, err := a.RoT.Attest(pcrSelection, nonce)
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
		Nonce:           nonce,
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
