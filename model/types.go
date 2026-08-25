package model

import (
	"encoding/binary"
	"time"
)

// QuotePayload rappresenta l'evidenza prodotta dall'Agent/TPM.
//
// CAMBIO RISPETTO ALLA FASE 1: in Fase 1 questa struct portava un digest
// PCR e una firma "fatti in casa" (SignedBytes()+RSA). In Fase 2 la vera
// prova crittografica è la struttura TPM standard TPMS_ATTEST + TPMT_SIGNATURE
// (definite dal TCG), che NON reinventiamo: la incapsuliamo opaca dentro
// AttestationBlob, prodotta da client.Key.Attest() e verificata da
// server.VerifyAttestation() (entrambe di google/go-tpm-tools). I campi
// InstanceID/Generation restano nostri: servono al PROTOCOLLO applicativo
// (RA5G), non fanno parte dello standard TPM e non sono coperti dalla
// firma del TPM — per questo li teniamo come metadata "di trasporto" a
// fianco del blob, autenticati indirettamente dal fatto che il Verifier
// li lega, nella propria logica, all'istanza registrata (vedi verifier.go).
type QuotePayload struct {
	InstanceID string `json:"instance_id"`
	Generation int    `json:"generation"`

	// Nonce è la stessa challenge che il Verifier si aspetta di ritrovare
	// dentro il campo ExtraData del TPMS_ATTEST incapsulato in
	// AttestationBlob: è la NOSTRA copia "in chiaro" del nonce, usata dal
	// Verifier per il bookkeeping di anti-replay (pendingNonces/
	// usedNonces in verifier.go) PRIMA ancora di aprire il blob TPM.
	// La verifica che coincida DAVVERO con quello firmato dal TPM è
	// delegata a server.VerifyAttestation tramite server.VerifyOpts.Nonce.
	Nonce []byte `json:"nonce"`

	// AttestationBlob contiene la serializzazione Protobuf di un
	// *attestpb.Attestation prodotto da client.Key.Attest(): include la/e
	// TPM2_Quote (TPMS_ATTEST + TPMT_SIGNATURE) su una o più PCR bank,
	// più l'event log di boot/IMA. È l'equivalente, in Fase 2, sia del
	// vecchio campo Signature/PCRDigest della Fase 1, sia del ritorno di
	// GetMeasurementLog(): go-tpm-tools li incapsula insieme in un unico
	// messaggio, perché il Verifier deve valutarli in modo congiunto
	// (l'event log da solo non è affidabile senza la quote che lo lega ai
	// PCR realmente misurati dal TPM).
	AttestationBlob []byte `json:"attestation_blob"`
}

// Token è il visto d'accesso a tempo emesso dal Verifier per l'Enforcement Plane
// INVARIATO rispetto alla Fase 1: il Token non ha mai avuto a che fare col
// TPM — è firmato con la chiave operativa del Verifier (sk_V), un servizio
// software ordinario.
type Token struct {
	InstanceID string    `json:"instance_id"`
	Generation int       `json:"generation"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	SignatureV []byte    `json:"signature_v"` // Firma del Verifier (sk_V)
}

// GenerationLinkCert lega crittograficamente due generazioni durante migrazioni/restart
// INVARIATO rispetto alla Fase 1, stesso motivo del Token.
type GenerationLinkCert struct {
	InstanceID    string `json:"instance_id"`
	OldGeneration int    `json:"old_generation"`
	NewGeneration int    `json:"new_generation"`
	MigNonce      []byte `json:"mig_nonce"`
	TargetHost    string `json:"target_host"`
	SignatureV    []byte `json:"signature_v"`
}

// SignedBytes produce la codifica canonica coperta dalla firma del
// Verifier (sk_V) per un Token. INVARIATA rispetto alla Fase 1.
func (t Token) SignedBytes() []byte {
	buf := make([]byte, 0, len(t.InstanceID)+24)
	buf = append(buf, []byte(t.InstanceID)...)
	gen := make([]byte, 8)
	binary.BigEndian.PutUint64(gen, uint64(t.Generation))
	buf = append(buf, gen...)
	issued, _ := t.IssuedAt.MarshalBinary()
	expires, _ := t.ExpiresAt.MarshalBinary()
	buf = append(buf, issued...)
	buf = append(buf, expires...)
	return buf
}

// SignedBytes produce la codifica canonica coperta dalla firma del
// Verifier (sk_V) per un GenerationLinkCert. INVARIATA rispetto alla Fase 1.
func (g GenerationLinkCert) SignedBytes() []byte {
	buf := make([]byte, 0, len(g.InstanceID)+len(g.MigNonce)+len(g.TargetHost)+16)
	buf = append(buf, []byte(g.InstanceID)...)
	old := make([]byte, 8)
	binary.BigEndian.PutUint64(old, uint64(g.OldGeneration))
	buf = append(buf, old...)
	nw := make([]byte, 8)
	binary.BigEndian.PutUint64(nw, uint64(g.NewGeneration))
	buf = append(buf, nw...)
	buf = append(buf, g.MigNonce...)
	buf = append(buf, []byte(g.TargetHost)...)
	return buf
}

// BurnRecord registra l'invalidazione permanente di una generazione.
// INVARIATO rispetto alla Fase 1.
type BurnRecord struct {
	InstanceID string    `json:"instance_id"`
	Generation int       `json:"generation"`
	RevokedAt  time.Time `json:"revoked_at"`
	Reason     string    `json:"reason"`
}
