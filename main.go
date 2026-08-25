// Comando dimostrativo Fase 2: stesso scenario end-to-end della Fase 1
// (bootstrap, continuous attestation, replay attack, fail-closed), ma con
// l'Agent che parla DAVVERO con un TPM 2.0 — qui il simulatore software di
// google/go-tpm-tools, sostituibile con /dev/tpmrm0 cambiando UNA riga
// (vedi commento su rot.OpenDevice più sotto) per girare su hardware reale.
//
// AGGIORNAMENTO: lo scenario di Replay Attack ora dimostra anche il canale
// di revoca immediata Verifier->Enforcement (v.OnRevoke/e.Revoke): il
// routing viene negato nello stesso istante in cui il replay viene
// rilevato, non più solo alla scadenza naturale del token.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"ra5g/agent"
	"ra5g/enforcement"
	"ra5g/model"
	"ra5g/rot"
	"ra5g/verifier"
)

const instanceID = "vnf-instance-001"

func section(title string) {
	fmt.Println()
	fmt.Println("=== " + title + " ===")
}

func main() {
	section("SETUP")

	v, err := verifier.New()
	must(err)

	// Apre la connessione verso il TPM. Per usare un chip reale, sostituisci
	// questa riga con:
	//   tpmConn, err := rot.OpenDevice()
	// (su Linux userà il device di sistema di default, su Windows il
	// servizio TBS). Nient'altro nel resto del file cambia: è esattamente
	// il punto dell'interfaccia rot.RootOfTrust.
	tpmConn, err := rot.OpenSimulator()
	must(err)
	defer tpmConn.Close()

	root, err := rot.NewTPM2RootOfTrust(tpmConn)
	must(err)
	defer root.Close()

	a := agent.NewAgent(instanceID, root)

	// FIX (scoperto testando end-to-end): client.Key.Attest quota SEMPRE
	// l'intero banco PCR SHA-256, non un sottoinsieme scelto da noi (vedi
	// il commento su rot.FullPCRSelection per i dettagli). Usiamo quindi
	// QUESTA selezione — e non un sottoinsieme arbitrario come {0,1} — sia
	// per leggere il Golden Measurement in fase di onboarding sia, più
	// sotto, come parametro "informativo" passato a GetTPMQuote: se la
	// selezione usata per il Golden Measurement non combacia esattamente
	// con quella che la quote reale copre, il confronto in verifier.go
	// fallisce sempre — non per un attacco, ma per un disallineamento tra
	// cosa abbiamo misurato noi e cosa il TPM ha davvero firmato.
	pcrSelection := rot.FullPCRSelection()

	// Simula il boot "genuino" dell'istanza: bootloader e OS image
	// noti-buoni, estesi DAVVERO nei PCR del TPM (reale o simulato).
	must(a.ExtendPCR(0, []byte("genuine-bootloader-v1.4")))
	must(a.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")))

	// Calcola il Golden Measurement come digest COMBINATO dei PCR
	// selezionati, replicando lo stesso algoritmo che il TPM userà
	// internamente in TPM2_Quote per produrre PCRDigest (concatenazione
	// dei valori PCR nell'ordine di selezione, poi SHA-256) — per questo
	// il confronto in verifier.go, che estrae il digest reale dal
	// TPMS_ATTEST, potrà coincidere byte-per-byte con questo valore
	// calcolato qui in fase di onboarding.
	pcrValues, err := root.ReadPCRs(pcrSelection)
	must(err)
	golden := combinedPCRDigest(pcrValues, pcrSelection)

	v.RegisterInstance(instanceID, root.PublicKey(), golden)

	e := enforcement.New(v.PublicKey())
	fmt.Println("Verifier, Agent (TPM-backed) ed Enforcement Plane inizializzati.")
	fmt.Println("Istanza registrata con Golden Measurement letto dal TPM.")

	// Collega il canale di revoca immediata: registriamo presso il
	// Verifier un hook che, quando una generazione viene bruciata (per
	// qualunque motivo: replay, mismatch PCR, revoca manuale...), chiama
	// SUBITO e.Revoke(...) invece di aspettare che il token corrente
	// scada da solo (fino a DefaultTokenTTL = 30s). Questa singola riga è
	// tutto ciò che main.go deve fare: la logica di "quando" chiamare
	// l'hook, e la garanzia che venga chiamato a lock rilasciato, sono
	// già incapsulate dentro verifier.go (vedi VerifyQuote/OnRevoke lì).
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})

	// ------------------------------------------------------------------
	// 1) BOOTSTRAP (g = 0)
	// ------------------------------------------------------------------
	section("1) BOOTSTRAP (generation 0)")

	tBoot0 := time.Now()

	nonce0, err := v.GenerateNonce(instanceID)
	must(err)

	quote0, err := a.GetTPMQuote(0, nonce0, pcrSelection)
	must(err)

	ok := v.VerifyQuote(instanceID, *quote0, nonce0)
	fmt.Printf("VerifyQuote(gen=0): %v\n", ok)
	if !ok {
		log.Fatal("bootstrap fallito inaspettatamente")
	}

	token0, err := v.IssueToken(instanceID, 0)
	must(err)
	fmt.Printf("Token emesso: generation=%d, expires_at=%s\n", token0.Generation, token0.ExpiresAt.Format(time.RFC3339))

	e.UpdateRoutingRules(token0)
	fmt.Printf("Enforcement: instradamento consentito = %v\n", e.IsRoutingAllowed(instanceID))
	fmt.Printf("Bootstrap Latency (T_boot), include round-trip TPM reale: %s\n", time.Since(tBoot0))

	// ------------------------------------------------------------------
	// 2) CONTINUOUS ATTESTATION (rinnovo della lease, stessa generazione)
	// ------------------------------------------------------------------
	section("2) CONTINUOUS ATTESTATION (rinnovo lease)")

	tRenew := time.Now()

	nonce1, err := v.GenerateNonce(instanceID)
	must(err)

	quote1, err := a.GetTPMQuote(0, nonce1, pcrSelection)
	must(err)

	ok = v.VerifyQuote(instanceID, *quote1, nonce1)
	fmt.Printf("VerifyQuote(rinnovo gen=0): %v\n", ok)
	if !ok {
		log.Fatal("rinnovo continuous attestation fallito inaspettatamente")
	}

	token1, err := v.IssueToken(instanceID, 0)
	must(err)
	fmt.Printf("Token rinnovato: generation=%d, expires_at=%s\n", token1.Generation, token1.ExpiresAt.Format(time.RFC3339))

	e.UpdateRoutingRules(token1)
	fmt.Printf("Enforcement: instradamento consentito = %v\n", e.IsRoutingAllowed(instanceID))
	fmt.Printf("Handover/Renewal Latency (round-trip TPM reale): %s\n", time.Since(tRenew))

	// ------------------------------------------------------------------
	// 3) TENTATIVO DI REPLAY ATTACK
	// ------------------------------------------------------------------
	section("3) REPLAY ATTACK (riutilizzo del quote già consumato)")

	// Prima di rigiocare il quote, verifichiamo che il routing sia ancora
	// concesso (conseguenza del rinnovo avvenuto al passo precedente): è
	// il punto di partenza rispetto a cui misuriamo l'effetto della
	// revoca immediata qui sotto.
	fmt.Printf("Enforcement: instradamento consentito PRIMA del replay = %v\n", e.IsRoutingAllowed(instanceID))

	replayOK := v.VerifyQuote(instanceID, *quote1, nonce1)
	fmt.Printf("VerifyQuote(replay di quote1): %v (atteso: false)\n", replayOK)

	// A differenza della versione precedente di questo file, qui il
	// routing risulta già negato SUBITO dopo la riga precedente, non dopo
	// fino a 30 secondi di attesa: VerifyQuote ha rilevato il replay,
	// bruciato la generazione, e l'hook registrato sopra ha chiamato
	// e.Revoke(...) PRIMA che questa riga venisse eseguita — nessuna
	// attesa, nessun timer coinvolto. Corrisponde al passo "Revoca
	// Immediata Routing" della Fase 4 del sequence diagram del protocollo.
	fmt.Printf("Enforcement: instradamento consentito DOPO il replay (immediato, senza attendere il TTL) = %v (atteso: false)\n", e.IsRoutingAllowed(instanceID))

	records := v.BurnRecords(instanceID)
	fmt.Printf("BurnRecords registrati per %s: %d\n", instanceID, len(records))
	for _, r := range records {
		fmt.Printf("  - generation=%d motivo=%q revoked_at=%s\n", r.Generation, r.Reason, r.RevokedAt.Format(time.RFC3339))
	}

	_, errIssue := v.IssueToken(instanceID, 0)
	fmt.Printf("Tentativo di IssueToken su generazione bruciata: errore = %v\n", errIssue)

	// "Migliorato la gestione del replay attack" — è la risposta, non la rilevazione, ad essere migliorata.
	// Il rilevamento del replay (confronto nonce, usedNonces) era già presente e corretto fin dalla Fase 1/2 — non l'ho toccato.
	// Quello che è cambiato è cosa succede dopo che il replay viene rilevato: prima il routing restava aperto fino a 30s (TTL),
	// ora si chiude nello stesso istante. È una distinzione importante da avere chiara: la sicurezza crittografica non è cambiata, è cambiata la velocità di reazione.

	// ------------------------------------------------------------------
	// 4) FAIL-CLOSED DEFAULT
	// ------------------------------------------------------------------
	section("4) FAIL-CLOSED DEFAULT")

	expiredToken := &model.Token{
		InstanceID: instanceID,
		Generation: 0,
		IssuedAt:   time.Now().Add(-2 * time.Minute),
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
	}
	expiredToken.SignatureV = randomBytes(256)

	valid := e.ValidateToken(expiredToken)
	fmt.Printf("ValidateToken(token scaduto/non firmato correttamente): %v (atteso: false)\n", valid)

	e.UpdateRoutingRules(expiredToken)
	fmt.Printf("Enforcement: instradamento consentito dopo token invalido = %v (atteso: false)\n", e.IsRoutingAllowed(instanceID))

	neverAttested := "vnf-instance-999-mai-vista"
	fmt.Printf("Enforcement: instradamento per istanza mai attestata (%s) = %v (atteso: false)\n",
		neverAttested, e.IsRoutingAllowed(neverAttested))

	section("FINE SIMULAZIONE (Fase 2, TPM simulato)")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// combinedPCRDigest replica, in Go puro, il calcolo che il TPM esegue
// internamente per produrre il campo PCRDigest di un TPMS_QUOTE_INFO:
// concatena i valori PCR nell'ORDINE della selezione data, poi ne calcola
// SHA-256. Usata SOLO in fase di onboarding (qui in main.go) per derivare
// il Golden Measurement da uno stato letto direttamente dal TPM — non è
// usata nel path di verifica, che invece estrae il digest reale già
// prodotto e firmato dal TPM (vedi verifier.go).
func combinedPCRDigest(pcrValues map[int][]byte, pcrSelection []int) []byte {
	h := sha256.New()
	for _, idx := range pcrSelection {
		h.Write(pcrValues[idx])
	}
	return h.Sum(nil)
}
