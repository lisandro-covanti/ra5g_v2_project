package model

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// ContextTag identifica IL TIPO DI OPERAZIONE per cui una quote TPM è
// stata richiesta (bootstrap, rinnovo di lease, migrazione...).
//
// PERCHÉ SERVE: senza un context-tag, il nonce che il TPM firma è "nudo"
// — non porta alcuna informazione su PER COSA è stato richiesto. Una
// quote valida prodotta in risposta a una challenge di rinnovo, in
// teoria, potrebbe essere ripresentata con successo come risposta a una
// challenge di un contesto diverso (es. una migrazione), perché nulla nel
// dato effettivamente firmato dal TPM lo impedisce esplicitamente — il
// nonce da solo garantisce "non è un replay dello STESSO scambio", non
// "è la risposta al tipo di domanda giusta". Legare il tag al nonce prima
// di firmarlo (vedi ContextBoundNonce sotto) chiude questo spiraglio.
type ContextTag byte

const (
	// ContextTagBoot identifica una challenge di Bootstrap (Fase 1:
	// prima attestazione di una nuova generazione, g=0 o una nuova
	// generazione dopo un riavvio).
	ContextTagBoot ContextTag = 0x01

	// ContextTagRenew identifica una challenge di Continuous Attestation
	// (Fase 2: rinnovo della lease, stessa generazione).
	ContextTagRenew ContextTag = 0x02

	// ContextTagMigrate identifica una challenge di Migrazione
	// Cooperativa (Fase 3, non ancora implementata): riservato già da
	// ora, così che il meccanismo di context-binding sia pronto quando
	// implementeremo quella fase, invece di doverlo introdurre in corsa.
	ContextTagMigrate ContextTag = 0x03
)

// String restituisce un nome leggibile del tag, usato solo per log/errori
// (es. nei motivi dei BurnRecord) — non incide sulla codifica usata da
// ContextBoundNonce, che lavora sul valore byte grezzo, non sulla stringa.
func (c ContextTag) String() string {
	switch c {
	case ContextTagBoot:
		return "boot"
	case ContextTagRenew:
		return "renew"
	case ContextTagMigrate:
		return "migrate"
	default:
		return "sconosciuto"
	}
}

// ContextBoundNonce calcola il valore EFFETTIVAMENTE dato in pasto al TPM
// come ExtraData di TPM2_Quote, legando insieme tag, instanceID,
// generation e il nonce originale del Verifier in un unico digest SHA-256.
//
// Sia l'Agent (che lo calcola prima di chiamare Attest, vedi agent.go) sia
// il Verifier (che lo ricalcola prima di chiamare server.VerifyAttestation,
// vedi verifier.go) DEVONO usare esattamente questa stessa funzione, con
// gli stessi valori, altrimenti la verifica fallirebbe SEMPRE anche per
// una quote del tutto legittima — è lo stesso principio già visto per
// Token.SignedBytes()/GenerationLinkCert.SignedBytes(): una codifica
// canonica condivisa tra chi firma/produce e chi verifica.
//
// La codifica usa un prefisso di LUNGHEZZA per instanceID (l'unico campo
// di lunghezza variabile che precede altri campi) per evitare ambiguità
// di concatenazione — lo stesso accorgimento già discusso per
// QuotePayload.SignedBytes() in Fase 1 (rimosso in Fase 2 per quel campo,
// ma il principio resta valido e qui torna a servire).
func ContextBoundNonce(tag ContextTag, instanceID string, generation int, nonce []byte) []byte {
	h := sha256.New()

	h.Write([]byte{byte(tag)})

	idLen := make([]byte, 4)
	binary.BigEndian.PutUint32(idLen, uint32(len(instanceID)))
	h.Write(idLen)
	h.Write([]byte(instanceID))

	gen := make([]byte, 8)
	binary.BigEndian.PutUint64(gen, uint64(generation))
	h.Write(gen)

	h.Write(nonce)

	return h.Sum(nil)
}

// MigrationSourceBoundNonce è l'equivalente di ContextBoundNonce
// specifico per la quote prodotta dall'istanza USCENTE durante una
// migrazione (Fase 3). Rispetto a ContextBoundNonce, lega anche
// TargetHost: nel sequence diagram del protocollo, la quote dell'istanza
// uscente è firmata su H('migrate' || instanceID || oldGeneration ||
// n_mig || H_dst) — l'host di destinazione fa parte di ciò che l'istanza
// uscente attesta, non solo un dato di trasporto.
//
// PERCHÉ SERVE (oltre al tag): senza questo, un attaccante che
// intercetta una quote di migrazione legittima (prodotta col consenso
// dell'istanza per migrare verso l'host A) potrebbe presentarla al
// Verifier sostenendo che la migrazione è diretta verso un host B
// diverso — nulla nella quote lo impedirebbe, perché TargetHost sarebbe
// solo un campo "di trasporto" non coperto dalla firma TPM. Legandolo nel
// digest firmato, un TargetHost alterato invalida la firma.
//
// Il tag è sempre implicitamente ContextTagMigrate (non è un parametro:
// questa funzione esiste solo per quel contesto, a differenza della
// ContextBoundNonce generica usata per Boot/Renew e per la quote
// dell'istanza ENTRANTE in migrazione, che non necessita di questo
// legame aggiuntivo con l'host — vedi il commento su CompleteMigration in
// verifier.go per il perché quella resta sulla ContextBoundNonce generica).
func MigrationSourceBoundNonce(instanceID string, oldGeneration int, nonce []byte, targetHost string) []byte {
	h := sha256.New()

	h.Write([]byte{byte(ContextTagMigrate)})

	idLen := make([]byte, 4)
	binary.BigEndian.PutUint32(idLen, uint32(len(instanceID)))
	h.Write(idLen)
	h.Write([]byte(instanceID))

	gen := make([]byte, 8)
	binary.BigEndian.PutUint64(gen, uint64(oldGeneration))
	h.Write(gen)

	h.Write(nonce)

	// FIX (scoperto da TestMigrationSourceBoundNonceDiversoDaContextBoundNonce):
	// TargetHost va SEMPRE preceduto dalla propria lunghezza, anche
	// quando è la stringa vuota. Senza questo prefisso, con targetHost=""
	// la scrittura sotto ("h.Write([]byte(targetHost))") aggiunge ZERO
	// byte al digest — rendendo l'output di questa funzione IDENTICO,
	// byte per byte, a quello di ContextBoundNonce(ContextTagMigrate,
	// instanceID, generation, nonce): le due funzioni collidevano ogni
	// volta che targetHost era vuoto, vanificando la distinzione tra
	// "quote di Bootstrap/Renew con tag Migrate" e "quote di migrazione
	// del lato sorgente". Scrivendo SEMPRE i 4 byte di lunghezza (anche
	// per lunghezza zero), l'output di questa funzione è garantito più
	// lungo — e quindi diverso — da quello di ContextBoundNonce a parità
	// di tutti gli altri campi, indipendentemente dal valore di
	// targetHost.
	hostLen := make([]byte, 4)
	binary.BigEndian.PutUint32(hostLen, uint32(len(targetHost)))
	h.Write(hostLen)
	h.Write([]byte(targetHost))

	return h.Sum(nil)
}

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

	// Tag identifica per quale tipo di operazione questa quote è stata
	// prodotta (vedi ContextTag sopra). Il Verifier lo confronta con il
	// tag che si aspettava per quella specifica challenge, e lo include
	// nel calcolo di ContextBoundNonce prima di validare la firma TPM.
	Tag ContextTag `json:"tag"`

	// TargetHost è valorizzato SOLO nella quote prodotta dall'istanza
	// USCENTE durante una migrazione (Fase 3, tag ContextTagMigrate): è
	// l'host verso cui la migrazione è diretta, e viene legato
	// crittograficamente alla quote tramite MigrationSourceBoundNonce
	// (vedi sotto) — impedisce che una quote di migrazione legittima,
	// intercettata, venga "dirottata" verso un host diverso da quello per
	// cui l'istanza uscente ha dato il proprio consenso.
	TargetHost string `json:"target_host,omitempty"`

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
