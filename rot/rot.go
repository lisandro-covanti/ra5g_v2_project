// Package rot (Root of Trust) isola OGNI dipendenza diretta dalle librerie
// TPM dietro un'interfaccia Go. È la risposta diretta al problema di
// "dipendenza da una libreria/vendor specifico" discusso in precedenza:
// agent.go NON importa google/go-tpm-tools — importa solo questo package,
// e dipende dall'interfaccia RootOfTrust, non dal tipo concreto.
//
// Se domani si volesse passare a un'altra libreria (es. il "TPMDirect" API
// più moderno di go-tpm, oppure google/go-attestation per il flusso
// completo di certificazione EK→AK, oppure una libreria di un vendor per
// un secure element diverso da un TPM), basterebbe scrivere un nuovo tipo
// che implementa RootOfTrust in questo stesso package (o in uno nuovo) e
// cambiare UNA riga in main.go — senza toccare agent.go, verifier.go, né
// la logica di business del protocollo RA5G.
package rot

import (
	"crypto"
	"fmt"
	"io"

	tpmtoolsclient "github.com/google/go-tpm-tools/client"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// FullPCRSelection restituisce l'elenco COMPLETO degli indici PCR (sul
// banco SHA-256) che client.Key.Attest include SEMPRE nella quote.
//
// FIX (scoperto testando end-to-end): a differenza di quanto avevo
// assunto scrivendo la prima versione di questo file, client.Key.Attest
// NON offre alcun modo di restringere la quote a un sottoinsieme di PCR —
// la struct AttestOpts espone solo Nonce e TCGEventLog, nessun campo di
// selezione PCR. La quote prodotta copre SEMPRE l'intero banco (tutti i
// PCR del TPM, tipicamente 24), indipendentemente da cosa passiamo come
// "pcrSelection" alle nostre funzioni. Questa funzione restituisce
// esattamente quell'insieme completo, così che main.go possa calcolare il
// Golden Measurement sugli STESSI PCR che la quote reale coprirà — se
// calcolato solo su un sottoinsieme (come nella versione precedente,
// erroneamente limitata a {0,1}), il confronto in verifier.go fallirebbe
// SEMPRE, non per un attacco reale ma per un disallineamento tra cosa
// abbiamo misurato noi e cosa il TPM ha effettivamente firmato.
//
// Non richiede una connessione TPM aperta (non ha un receiver *TPM2RootOfTrust):
// è pura logica desunta dalla libreria, la stessa usata internamente da
// client.Key.Attest per decidere cosa quotare.
func FullPCRSelection() []int {
	return tpmtoolsclient.FullPcrSel(tpm2.AlgSHA256).PCRs
}

// RootOfTrust è l'interfaccia che l'Agent usa per produrre evidenza
// firmata dal TPM. Qualunque implementazione — TPM reale, simulatore
// software, o (in futuro) altra tecnologia di secure element — deve
// soddisfare solo questi tre metodi.
type RootOfTrust interface {
	// PublicKey restituisce la chiave pubblica della Attestation Key (AK),
	// da comunicare fuori banda al Verifier in fase di onboarding
	// (RegisterInstance). Il tipo di ritorno è l'interfaccia generica
	// crypto.PublicKey (non specificamente *rsa.PublicKey), perché
	// un'implementazione futura potrebbe usare una AK ECC.
	PublicKey() crypto.PublicKey

	// ExtendPCR estende un registro PCR con un nuovo evento di misurazione
	// (equivalente concettuale di quello che farebbero firmware/bootloader/
	// IMA su un boot reale; qui lo esponiamo per poter simulare/testare uno
	// stato "genuino" e uno stato "compromesso" senza dover riavviare
	// davvero la macchina).
	ExtendPCR(pcrIndex int, event []byte) error

	// ReadPCRs legge il valore CORRENTE dei PCR indicati, senza produrre
	// una quote firmata. Serve in fase di onboarding/provisioning (fuori
	// dal path critico di attestazione) per calcolare il Golden
	// Measurement a partire da uno stato software noto-buono — analogo
	// concettuale del vecchio Agent.PCRDigest() della Fase 1, ma qui i
	// valori sono letti dal TPM reale, non calcolati in software.
	ReadPCRs(pcrSelection []int) (map[int][]byte, error)

	// Attest produce l'evidenza TPM completa (quote + event log) per i
	// PCR indicati, legata al nonce fornito. Il tipo di ritorno è quello
	// definito da google/go-tpm-tools: un messaggio Attestation che
	// incapsula TPMS_ATTEST + TPMT_SIGNATURE conformi allo standard TCG.
	Attest(pcrSelection []int, nonce []byte) (*attestpb.Attestation, error)

	// Close rilascia le risorse TPM (handle, connessione al device o al
	// simulatore). Va sempre chiamato quando l'Agent non serve più.
	Close() error
}

// TPM2RootOfTrust è l'implementazione di RootOfTrust basata su
// google/go-tpm-tools, che a sua volta usa google/go-tpm per il trasporto
// del protocollo TPM 2.0 standard TCG. Funziona identica sia con un vero
// chip TPM 2.0 (qualunque vendor: Infineon, STMicroelectronics, Nuvoton,
// fTPM AMD, Intel PTT...) sia con un emulatore software, perché entrambi
// parlano lo stesso protocollo TPM2 standardizzato: quello che cambia è
// solo COME viene aperta la connessione rw (vedi OpenSimulator/OpenDevice
// più sotto), non il resto del codice.
type TPM2RootOfTrust struct {
	rw io.ReadWriteCloser
	ak *tpmtoolsclient.Key // Attestation Key creata/caricata nel TPM
}

// OpenSimulator apre una connessione verso un TPM 2.0 SOFTWARE, emulato
// in-process dal simulatore di riferimento di Google (basato sullo stesso
// simulatore di riferimento Microsoft usato anche da swtpm). Utile per
// sviluppo/test quando non si ha accesso fisico a un chip TPM — è
// l'equivalente, in Fase 2, di quanto indicato nel documento originale
// come "integrazione con un emulatore TPM 2.0 (swtpm)": non è
// letteralmente lo stesso processo swtpm, ma implementa lo stesso
// simulatore di riferimento ed espone la stessa interfaccia io.ReadWriter,
// quindi il resto del codice (compreso questo file) è IDENTICO che si usi
// questo o un vero /dev/tpmrm0.
func OpenSimulator() (io.ReadWriteCloser, error) {
	sim, err := simulator.Get()
	if err != nil {
		return nil, fmt.Errorf("rot: impossibile avviare il simulatore TPM: %w", err)
	}
	return sim, nil
}

// OpenDevice apre una connessione verso un TPM 2.0 HARDWARE reale.
//
// FIX rispetto alla revisione precedente: tpm2.OpenTPM ha una firma
// DIVERSA a seconda della piattaforma di compilazione — su Linux accetta
// un path opzionale al device node (es. "/dev/tpmrm0"), su Windows non
// accetta alcun argomento perché l'accesso avviene sempre tramite il
// servizio di sistema TBS (TPM Base Services), non un device node. Per
// restare compilabile su entrambe le piattaforme senza build tag separati,
// chiamiamo OpenTPM() senza argomenti: su Linux userà il device di default
// del sistema, su Windows aprirà TBS. Se in futuro serve un path Linux
// specifico, va introdotto con un file _linux.go a parte (build-tag-based),
// non richiamando qui una firma che su Windows non esiste.
func OpenDevice() (io.ReadWriteCloser, error) {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("rot: impossibile aprire il TPM di sistema: %w", err)
	}
	return rwc, nil
}

// NewTPM2RootOfTrust crea (o carica, se già presente nel TPM) una
// Attestation Key RSA nella gerarchia Owner del TPM connesso tramite rw, e
// restituisce un RootOfTrust pronto all'uso.
//
// NOTA IMPORTANTE (limite noto, da leggere): client.AttestationKeyRSA
// crea l'AK ma NON esegue da sola la certificazione EK→AK (challenge
// TPM2_ActivateCredential contro un certificato EK di fabbrica) discussa
// in precedenza. Questo significa che, così com'è, il Verifier che riceve
// questa AKPublicKey deve ancora fidarsi "per definizione" che provenga
// da un TPM genuino — esattamente il gap di provisioning descritto prima,
// non ancora chiuso. Chiuderlo richiede un passo di enrollment aggiuntivo
// (EK cert chain + ActivateCredential), fuori dallo scope di questo
// scheletro Fase 2: qui l'obiettivo è sostituire la crittografia simulata
// con vera crittografia TPM-backed, non ancora l'intera catena di fiducia
// hardware end-to-end.
func NewTPM2RootOfTrust(rw io.ReadWriteCloser) (*TPM2RootOfTrust, error) {
	ak, err := tpmtoolsclient.AttestationKeyRSA(rw)
	if err != nil {
		return nil, fmt.Errorf("rot: creazione/caricamento AK fallita: %w", err)
	}
	return &TPM2RootOfTrust{rw: rw, ak: ak}, nil
}

// PublicKey implementa RootOfTrust.
func (t *TPM2RootOfTrust) PublicKey() crypto.PublicKey {
	return t.ak.PublicKey()
}

// ExtendPCR implementa RootOfTrust usando TPM2_PCR_Event: il TPM stesso
// calcola l'hash dell'evento (su tutte le PCR bank supportate, es. SHA-256)
// ed estende il registro internamente — a differenza della Fase 1, qui
// NON calcoliamo noi l'hash in software: è il TPM a farlo, sui SUOI
// registri reali (o simulati fedelmente), che è esattamente il punto
// dell'avere un root of trust hardware.
func (t *TPM2RootOfTrust) ExtendPCR(pcrIndex int, event []byte) error {
	// Il tpmutil.Handle di un PCR corrisponde numericamente all'indice del
	// PCR stesso (i registri PCR occupano lo spazio di handle più basso,
	// 0x00000000..0x00000017 per i 24 PCR standard): la conversione diretta
	// int -> tpmutil.Handle è quindi corretta e non richiede una funzione
	// di lookup dedicata.
	pcrHandle := tpmutil.Handle(pcrIndex)
	if err := tpm2.PCREvent(t.rw, pcrHandle, event); err != nil {
		return fmt.Errorf("rot: PCREvent su PCR %d fallito: %w", pcrIndex, err)
	}
	return nil
}

// ReadPCRs implementa RootOfTrust usando client.ReadPCRs (go-tpm-tools),
// sul banco SHA-256, poi converte il risultato (una struttura Protobuf con
// chiavi uint32) nella mappa map[int][]byte richiesta dalla nostra
// interfaccia RootOfTrust.
func (t *TPM2RootOfTrust) ReadPCRs(pcrSelection []int) (map[int][]byte, error) {
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrSelection}
	pcrsProto, err := tpmtoolsclient.ReadPCRs(t.rw, sel)
	if err != nil {
		return nil, fmt.Errorf("rot: lettura PCR fallita: %w", err)
	}
	out := make(map[int][]byte, len(pcrsProto.GetPcrs()))
	for idx, val := range pcrsProto.GetPcrs() {
		out[int(idx)] = val
	}
	return out, nil
}

// Attest implementa RootOfTrust chiamando client.Key.Attest(), che
// internamente:
//  1. legge i valori correnti di TUTTI i PCR del banco SHA-256 (non solo
//     quelli passati in pcrSelection — vedi il commento su FullPCRSelection
//     più sopra: client.Key.Attest non supporta una selezione parziale);
//  2. raccoglie l'event log di boot/IMA disponibile (disattivato in questo
//     scheletro tramite TCGEventLog: []byte{}, vedi sotto);
//  3. esegue TPM2_Quote con la AK su quei PCR, includendo il nonce come
//     ExtraData del TPMS_ATTEST prodotto dal TPM;
//  4. impacchetta tutto in un unico messaggio Attestation.
//
// Il parametro pcrSelection resta nella firma di questo metodo per
// coerenza con l'interfaccia RootOfTrust e in previsione di una futura
// implementazione (magari basata sull'API TPMDirect di go-tpm, più
// granulare) che sappia davvero rispettarlo — ma con l'attuale libreria
// google/go-tpm-tools NON ha alcun effetto sulla quote prodotta: chi
// chiama questa funzione deve calcolare qualunque Golden Measurement
// usando rot.FullPCRSelection(), non un proprio sottoinsieme arbitrario.
//
// Tutto questo corrisponde, nel documento di analisi originale, alla
// combinazione di GetTPMQuote() + GetMeasurementLog(): in Fase 2 le due
// operazioni sono unificate perché il Verifier deve valutarle insieme per
// essere davvero utili (l'event log da solo, senza la quote che lo lega
// crittograficamente ai PCR, sarebbe falsificabile).
func (t *TPM2RootOfTrust) Attest(pcrSelection []int, nonce []byte) (*attestpb.Attestation, error) {
	attestation, err := t.ak.Attest(tpmtoolsclient.AttestOpts{
		Nonce: nonce,

		// FIX (scoperto testando su Windows): se il campo TCGEventLog
		// viene lasciato al suo valore di default (nil, "non impostato"),
		// client.Key.Attest prova AUTOMATICAMENTE a leggere l'event log
		// di boot direttamente dal sistema operativo ospite (su Linux da
		// /sys/kernel/security/tpm0/binary_bios_measurements). Quella
		// funzione di lettura è implementata SOLO per Linux nella libreria
		// google/go-tpm-tools: su qualunque altro OS (Windows, macOS)
		// fallisce con "only Linux supported", interrompendo l'intero
		// Attest anche quando si sta usando il simulatore software (che
		// comunque non avrebbe un vero event log di sistema coerente da
		// offrire). Per evitarlo, passiamo esplicitamente uno slice VUOTO
		// (non nil): un []byte{} soddisfa il controllo "è stato fornito
		// un valore" e disattiva il tentativo di auto-lettura dal SO,
		// mentre lasciare il campo del tutto assente (nil) lo riattiva.
		// Il prezzo di questa scelta: l'Attestation prodotta non porta
		// un vero TCG event log — accettabile per questo scheletro
		// Fase 2, dato che comunque la nostra logica applicativa (in
		// verifier.go) valuta il Golden Measurement sul PCRDigest
		// estratto dal TPMS_ATTEST, non sul contenuto dell'event log.
		TCGEventLog: []byte{},
	})
	if err != nil {
		return nil, fmt.Errorf("rot: Attest fallito: %w", err)
	}
	return attestation, nil
}

// Close implementa RootOfTrust.
//
// FIX rispetto alla revisione precedente: (*client.Key).Close() in questa
// versione di go-tpm-tools NON restituisce un error (a differenza di
// quanto avevo assunto) — è un semplice metodo di rilascio risorse senza
// valore di ritorno. Va quindi chiamato come istruzione a sé, non come
// espressione di cui controllare l'errore.
func (t *TPM2RootOfTrust) Close() error {
	t.ak.Close()
	return t.rw.Close()
}
