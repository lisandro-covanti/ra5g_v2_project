// Comando dimostrativo Fase 2+3: stesso scenario end-to-end della Fase 1
// (bootstrap, continuous attestation, replay attack, fail-closed), ma con
// l'Agent che parla DAVVERO con un TPM 2.0 — qui il simulatore software di
// google/go-tpm-tools, sostituibile con /dev/tpmrm0 cambiando UNA riga
// (vedi commento su rot.OpenDevice più sotto) per girare su hardware reale.
//
// AGGIORNAMENTO: lo scenario di Replay Attack ora dimostra anche il canale
// di revoca immediata Verifier->Enforcement (v.OnRevoke/e.Revoke): il
// routing viene negato nello stesso istante in cui il replay viene
// rilevato, non più solo alla scadenza naturale del token.
//
// AGGIORNAMENTO (v3): aggiunta la sezione 5, Migrazione Cooperativa
// (Fase 3 del sequence diagram del protocollo) — coordinamento a due
// lati (istanza sorgente + istanza target, su TPM fisicamente diversi),
// Atomic Commit, GenerationLinkCert. Vedi docs/06-fase3-migrazione.md.
//
// AGGIORNAMENTO (fix di blocco): la prima versione della sezione 5 apriva
// un secondo (e poi un terzo) simulatore TPM MENTRE quello del Setup era
// ancora attivo (i suoi defer scattavano solo alla fine di main). Aprire
// un simulatore google/go-tpm-tools/simulator mentre un altro è ancora
// vivo nello stesso processo Go risulta bloccarsi INDEFINITAMENTE (non
// solo lento: osservato per oltre 2 ore senza alcun progresso) — quasi
// certamente per uno stato interno globale/condiviso della libreria, non
// documentato esplicitamente, probabilmente ereditato dalla sua origine
// C e pensato per un solo simulatore per processo. La correzione
// strutturale: ogni simulatore vive dentro la propria funzione dedicata
// (runFasi1a4, runMigrationSourcePhase, runMigrationTargetPhase), il cui
// "defer Close()" scatta al RITORNO di QUELLA funzione — garantendo che
// non ci sia MAI più di un simulatore aperto contemporaneamente in tutto
// il programma.
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

func section(title string) {
	fmt.Println()
	fmt.Println("=== " + title + " ===")
}

func ts() string {
	return time.Now().Format("15:04:05")
}

func main() {
	v, err := verifier.New()
	must(err)

	e := enforcement.New(v.PublicKey())

	// Collega il canale di revoca immediata: registriamo presso il
	// Verifier un hook che, quando una generazione viene bruciata (per
	// qualunque motivo: replay, mismatch PCR, revoca manuale, Q_src non
	// valida in una migrazione...), chiama SUBITO e.Revoke(...) invece di
	// aspettare che il token corrente scada da solo (fino a
	// DefaultTokenTTL = 30s). La logica di "quando" chiamare l'hook, e la
	// garanzia che venga chiamato a lock rilasciato, sono incapsulate
	// dentro verifier.go (vedi VerifyQuote/OnRevoke lì).
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})

	pcrSelection := rot.FullPCRSelection()

	runFasi1a4(v, e, pcrSelection)
	runFase3Migrazione(v, e, pcrSelection)

	section("FINE SIMULAZIONE (Fase 2 + Fase 3, TPM simulato)")
}

// runFasi1a4 esegue Setup + Bootstrap + Continuous Attestation + Replay
// Attack + Fail-Closed per l'istanza "vnf-instance-001".
//
// PERCHÉ È UNA FUNZIONE A SÉ (non inline in main, come nella versione
// precedente): apre un simulatore TPM con "defer Close()" che scatta al
// RITORNO DI QUESTA FUNZIONE, non alla fine dell'intero programma —
// garantendo che, quando main() prosegue con runFase3Migrazione, NESSUN
// simulatore precedente sia ancora aperto. Vedi il commento in cima al
// file per il problema di blocco che questa struttura risolve.
func runFasi1a4(v *verifier.Verifier, e *enforcement.Enforcement, pcrSelection []int) {
	const instanceID = "vnf-instance-001"

	section("SETUP")

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
	fmt.Println("Verifier, Agent (TPM-backed) ed Enforcement Plane inizializzati.")
	fmt.Println("Istanza registrata con Golden Measurement letto dal TPM.")

	// ------------------------------------------------------------------
	// 1) BOOTSTRAP (g = 0)
	// ------------------------------------------------------------------
	section("1) BOOTSTRAP (generation 0)")

	tBoot0 := time.Now()

	nonce0, err := v.GenerateNonce(instanceID)
	must(err)

	quote0, err := a.GetTPMQuote(0, nonce0, pcrSelection, model.ContextTagBoot)
	must(err)

	ok := v.VerifyQuote(instanceID, *quote0, nonce0, model.ContextTagBoot)
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

	quote1, err := a.GetTPMQuote(0, nonce1, pcrSelection, model.ContextTagRenew)
	must(err)

	ok = v.VerifyQuote(instanceID, *quote1, nonce1, model.ContextTagRenew)
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

	replayOK := v.VerifyQuote(instanceID, *quote1, nonce1, model.ContextTagRenew)
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

	// La funzione termina QUI: i due "defer" (root.Close(), tpmConn.Close())
	// scattano ORA, prima che main() richiami runFase3Migrazione — il
	// simulatore TPM di questa fase è completamente chiuso e rilasciato.
}

// runFase3Migrazione orchestra lo scenario di Migrazione Cooperativa,
// delegando l'apertura/chiusura di ciascun simulatore TPM alle due
// funzioni sotto (runMigrationSourcePhase, runMigrationTargetPhase), MAI
// sovrapposte nel tempo — vedi il commento in cima al file.
//
// Scenario VOLUTAMENTE autonomo, con una propria istanza logica: non
// dipende dallo stato lasciato da runFasi1a4, dove "vnf-instance-001"
// risulta già bruciata dal replay attack simulato (BeginMigration
// richiede una generazione attualmente live, che quell'istanza non ha
// più). Rappresenta una SECONDA VNF che sta eseguendo normalmente su un
// host sorgente e deve essere spostata su un host di destinazione —
// ciascuno con il proprio TPM fisico, qui due simulatori software
// indipendenti (ma mai aperti contemporaneamente).
func runFase3Migrazione(v *verifier.Verifier, e *enforcement.Enforcement, pcrSelection []int) {
	section("5) MIGRAZIONE COOPERATIVA (g_0 -> g_1)")

	const migInstanceID = "vnf-instance-002-migrazione"
	const targetHost = "host-b.datacenter.local"

	migQuote0, migNonce0, nMig := runMigrationSourcePhase(v, e, pcrSelection, migInstanceID, targetHost)

	runMigrationTargetPhase(v, e, pcrSelection, migInstanceID, nMig)

	// --- Dimostrazione della guardia anti-generazione-superata: un vecchio
	// quote PRE-migrazione, anche se rigiocato, non può più interrompere
	// il routing della NUOVA generazione (vedi Enforcement.Revoke). Questa
	// verifica è puramente lato Verifier/Enforcement: non serve alcun
	// simulatore TPM aperto, migQuote0 è già un dato completamente
	// autonomo catturato in precedenza. ---
	replayPreMigrazione := v.VerifyQuote(migInstanceID, *migQuote0, migNonce0, model.ContextTagBoot)
	fmt.Printf("Replay del quote PRE-migrazione (gen=0): %v (atteso: false)\n", replayPreMigrazione)
	fmt.Printf("Enforcement dopo il replay pre-migrazione: instradamento consentito = %v (atteso: true — la generazione coinvolta è ormai superata)\n", e.IsRoutingAllowed(migInstanceID))
}

// runMigrationSourcePhase apre il simulatore TPM dell'host SORGENTE, lo
// usa per: un mini-Bootstrap dell'istanza (identico nella forma alla
// Fase 1) e la produzione di Q_src, poi lo CHIUDE (i due "defer" scattano
// al ritorno di QUESTA funzione) prima che runMigrationTargetPhase ne apra
// uno proprio — è la parte centrale della correzione al blocco descritto
// in cima al file.
func runMigrationSourcePhase(v *verifier.Verifier, e *enforcement.Enforcement, pcrSelection []int, migInstanceID, targetHost string) (migQuote0 *model.QuotePayload, migNonce0 []byte, nMig []byte) {
	fmt.Printf("[%s] Apertura simulatore TPM per l'host SORGENTE...\n", ts())
	srcConn, err := rot.OpenSimulator()
	must(err)
	defer srcConn.Close()

	fmt.Printf("[%s] Generazione Attestation Key (RSA 2048, software) per l'host SORGENTE — può richiedere qualche secondo...\n", ts())
	srcRoot, err := rot.NewTPM2RootOfTrust(srcConn)
	must(err)
	defer srcRoot.Close()
	fmt.Printf("[%s] Attestation Key SORGENTE pronta.\n", ts())

	srcAgent := agent.NewAgent(migInstanceID, srcRoot)

	must(srcAgent.ExtendPCR(0, []byte("genuine-bootloader-v1.4")))
	must(srcAgent.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")))
	srcPCRs, err := srcRoot.ReadPCRs(pcrSelection)
	must(err)
	srcGolden := combinedPCRDigest(srcPCRs, pcrSelection)
	v.RegisterInstance(migInstanceID, srcRoot.PublicKey(), srcGolden)

	// Bootstrap ordinario sull'host sorgente, identico nella forma alla Fase 1.
	migNonce0, err = v.GenerateNonce(migInstanceID)
	must(err)
	fmt.Printf("[%s] Produzione TPM2_Quote di bootstrap sull'host SORGENTE...\n", ts())
	migQuote0, err = srcAgent.GetTPMQuote(0, migNonce0, pcrSelection, model.ContextTagBoot)
	must(err)
	if ok := v.VerifyQuote(migInstanceID, *migQuote0, migNonce0, model.ContextTagBoot); !ok {
		log.Fatal("bootstrap dell'istanza di migrazione fallito inaspettatamente")
	}
	migToken0, err := v.IssueToken(migInstanceID, 0)
	must(err)
	e.UpdateRoutingRules(migToken0)
	fmt.Printf("[%s] Istanza %s avviata su host sorgente, generation=0, instradamento = %v\n", ts(), migInstanceID, e.IsRoutingAllowed(migInstanceID))

	// --- Avvio della migrazione: "Challenge Migrazione (nonce n_mig)" ---
	nMig, err = v.BeginMigration(migInstanceID, targetHost)
	must(err)
	fmt.Printf("Migrazione avviata verso %q: nonce n_mig generato.\n", targetHost)

	// Q_src: l'istanza SORGENTE (generation 0) acconsente esplicitamente
	// alla migrazione verso targetHost — nota il tag "migrate" e il
	// legame con H_dst, entrambi coperti dalla firma TPM tramite
	// model.MigrationSourceBoundNonce (vedi agent.go/model/types.go).
	fmt.Printf("[%s] Produzione TPM2_Quote di migrazione (Q_src) sull'host SORGENTE...\n", ts())
	qSrc, err := srcAgent.GetMigrationSourceQuote(0, nMig, pcrSelection, targetHost)
	must(err)
	srcOK := v.ValidateMigrationSource(migInstanceID, *qSrc)
	fmt.Printf("[%s] ValidateMigrationSource (Q_src): %v\n", ts(), srcOK)
	if !srcOK {
		log.Fatal("validazione di Q_src fallita inaspettatamente")
	}

	fmt.Printf("[%s] Chiusura del simulatore TPM dell'host SORGENTE...\n", ts())
	return migQuote0, migNonce0, nMig
}

// runMigrationTargetPhase apre il simulatore TPM dell'host TARGET —
// SOLO DOPO che runMigrationSourcePhase è già tornata e ha quindi già
// chiuso il proprio simulatore (garanzia data dall'ordine di chiamata
// sequenziale in runFase3Migrazione, non da un meccanismo di lock
// esplicito: in Go, senza l'uso di goroutine, il codice di una funzione
// gira sempre fino al suo "return" prima che l'istruzione successiva nel
// chiamante venga eseguita). Produce Q_dst ed esegue l'Atomic Commit.
func runMigrationTargetPhase(v *verifier.Verifier, e *enforcement.Enforcement, pcrSelection []int, migInstanceID string, nMig []byte) {
	fmt.Printf("[%s] Apertura simulatore TPM per l'host TARGET...\n", ts())
	dstConn, err := rot.OpenSimulator()
	must(err)
	defer dstConn.Close()

	fmt.Printf("[%s] Generazione Attestation Key (RSA 2048, software) per l'host TARGET — può richiedere qualche secondo...\n", ts())
	dstRoot, err := rot.NewTPM2RootOfTrust(dstConn)
	must(err)
	defer dstRoot.Close()
	fmt.Printf("[%s] Attestation Key TARGET pronta.\n", ts())

	dstAgent := agent.NewAgent(migInstanceID, dstRoot)

	// Boot misurato sull'host target: qui la stessa immagine software
	// della sorgente (stesso Golden Measurement); in un caso reale con
	// un aggiornamento contestuale alla migrazione i due Golden
	// potrebbero anche differire legittimamente.
	must(dstAgent.ExtendPCR(0, []byte("genuine-bootloader-v1.4")))
	must(dstAgent.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")))
	dstPCRs, err := dstRoot.ReadPCRs(pcrSelection)
	must(err)
	dstGolden := combinedPCRDigest(dstPCRs, pcrSelection)

	const newGeneration = 1
	fmt.Printf("[%s] Produzione TPM2_Quote (Q_dst) sull'host TARGET...\n", ts())
	qDst, err := dstAgent.GetTPMQuote(newGeneration, nMig, pcrSelection, model.ContextTagMigrate)
	must(err)

	fmt.Printf("[%s] CompleteMigration (Atomic Commit)...\n", ts())
	token, cert, commitOK := v.CompleteMigration(migInstanceID, newGeneration, *qDst, dstRoot.PublicKey(), dstGolden)
	fmt.Printf("[%s] CompleteMigration (Atomic Commit): %v\n", ts(), commitOK)
	if !commitOK {
		log.Fatal("Atomic Commit della migrazione fallito inaspettatamente")
	}
	fmt.Printf("GenerationLinkCert emesso: %d -> %d, target_host=%q\n", cert.OldGeneration, cert.NewGeneration, cert.TargetHost)

	e.UpdateRoutingRules(token)
	fmt.Printf("Enforcement dopo la migrazione: instradamento consentito = %v (sulla NUOVA generazione)\n", e.IsRoutingAllowed(migInstanceID))

	fmt.Printf("[%s] Chiusura del simulatore TPM dell'host TARGET...\n", ts())
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
