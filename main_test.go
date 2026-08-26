// Questo file dichiara "package main_test" — NON "package main" come
// main.go. Il suffisso "_test" lo rende un package "esterno" (black-box):
// vede SOLO l'API pubblica di agent/verifier/enforcement/rot (esattamente
// ciò che vedrebbe main.go, o un vero consumatore di questi package), non
// i dettagli interni. È la scelta giusta qui perché questi test
// verificano lo stesso scenario end-to-end che main.go dimostra a video,
// non i dettagli implementativi di un singolo package (quelli sono
// coperti da verifier_test.go ed enforcement_test.go, che invece sono
// white-box).
//
// A DIFFERENZA di verifier_test.go/enforcement_test.go, questi test SONO
// più lenti (decine di millisecondi ciascuno, non microsecondi) perché
// ciascuno apre un vero simulatore TPM 2.0 in-process e ci parla
// attraverso il protocollo TPM2 standard — lo stesso costo che main.go
// paga ad ogni esecuzione, qui moltiplicato per il numero di test.
package main_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"ra5g/agent"
	"ra5g/enforcement"
	"ra5g/model"
	"ra5g/rot"
	"ra5g/verifier"
)

// combinedPCRDigest è una copia della funzione OMONIMA e privata definita
// in main.go: essendo minuscola, non è visibile da un package esterno
// come questo (package main_test), quindi va ridichiarata qui. È
// l'unica vera duplicazione in questo file — se in futuro cambia
// l'algoritmo in main.go, va allineato anche qui (un promemoria per
// quando toccheremo la logica di Golden Measurement).
func combinedPCRDigest(pcrValues map[int][]byte, pcrSelection []int) []byte {
	h := sha256.New()
	for _, idx := range pcrSelection {
		h.Write(pcrValues[idx])
	}
	return h.Sum(nil)
}

// testSystem raggruppa i quattro attori che ogni test end-to-end deve
// istanziare (Verifier, Agent, Enforcement, selezione PCR) — evita di
// dover passare quattro valori separati in giro tra le funzioni helper.
type testSystem struct {
	verifier     *verifier.Verifier
	agent        *agent.Agent
	enforcement  *enforcement.Enforcement
	pcrSelection []int
	instanceID   string
}

// setupTestSystem replica ESATTAMENTE la sezione "SETUP" di main.go:
// crea il Verifier, apre un TPM simulato, crea l'Agent, misura un boot
// "genuino", calcola e registra il Golden Measurement, crea l'Enforcement
// e collega il canale di revoca immediata. Ogni test che lo chiama
// riparte da zero con il proprio simulatore TPM indipendente — nessuno
// stato è condiviso tra un test e l'altro, quindi l'ordine di esecuzione
// dei test non ha importanza (un requisito che go test assume sempre:
// i test devono poter girare in un ordine qualsiasi, anche in parallelo).
func setupTestSystem(t *testing.T) *testSystem {
	t.Helper()

	const instanceID = "vnf-instance-test"

	v, err := verifier.New()
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	tpmConn, err := rot.OpenSimulator()
	if err != nil {
		t.Fatalf("rot.OpenSimulator: %v", err)
	}
	// t.Cleanup registra questa chiusura per essere eseguita
	// automaticamente al termine del test (successo o fallimento non
	// importa) — equivalente di un "defer", ma gestito dal framework di
	// test invece che scritto a mano in ogni singola funzione Test*.
	t.Cleanup(func() { _ = tpmConn.Close() })

	root, err := rot.NewTPM2RootOfTrust(tpmConn)
	if err != nil {
		t.Fatalf("rot.NewTPM2RootOfTrust: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	a := agent.NewAgent(instanceID, root)
	pcrSelection := rot.FullPCRSelection()

	if err := a.ExtendPCR(0, []byte("genuine-bootloader-v1.4")); err != nil {
		t.Fatalf("ExtendPCR(0): %v", err)
	}
	if err := a.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")); err != nil {
		t.Fatalf("ExtendPCR(1): %v", err)
	}

	pcrValues, err := root.ReadPCRs(pcrSelection)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	golden := combinedPCRDigest(pcrValues, pcrSelection)

	v.RegisterInstance(instanceID, root.PublicKey(), golden)

	e := enforcement.New(v.PublicKey())
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})

	return &testSystem{
		verifier:     v,
		agent:        a,
		enforcement:  e,
		pcrSelection: pcrSelection,
		instanceID:   instanceID,
	}
}

// bootstrap esegue un ciclo completo di Bootstrap (challenge -> quote ->
// verifica -> token -> routing) e restituisce quote e nonce usati, che i
// test sul replay riutilizzeranno deliberatamente. t.Helper() fa sì che,
// se una delle asserzioni qui dentro fallisce, go test indichi la riga
// del TEST chiamante, non questa riga interna — messaggi di errore più
// utili quando si scorre l'output.
func bootstrap(t *testing.T, sys *testSystem) (*model.QuotePayload, []byte) {
	t.Helper()

	nonce, err := sys.verifier.GenerateNonce(sys.instanceID)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	quote, err := sys.agent.GetTPMQuote(0, nonce, sys.pcrSelection, model.ContextTagBoot)
	if err != nil {
		t.Fatalf("GetTPMQuote: %v", err)
	}

	if ok := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce, model.ContextTagBoot); !ok {
		t.Fatal("VerifyQuote deve restituire true per un bootstrap genuino")
	}

	token, err := sys.verifier.IssueToken(sys.instanceID, 0)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	sys.enforcement.UpdateRoutingRules(token)

	return quote, nonce
}

// TestBootstrap verifica la Fase 1: dopo un bootstrap riuscito, il
// routing deve essere consentito. Corrisponde a quanto verificavamo a
// occhio nella sezione "1) BOOTSTRAP" dell'output di main.go.
func TestBootstrap(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys)

	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("il routing deve essere consentito subito dopo un Bootstrap riuscito")
	}
}

// TestContinuousAttestationRinnovaIlToken verifica la Fase 2: un secondo
// giro di challenge/quote/verifica con la STESSA generazione (rinnovo
// della lease) deve avere successo e mantenere il routing aperto.
func TestContinuousAttestationRinnovaIlToken(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys)

	nonce, err := sys.verifier.GenerateNonce(sys.instanceID)
	if err != nil {
		t.Fatalf("GenerateNonce (rinnovo): %v", err)
	}

	quote, err := sys.agent.GetTPMQuote(0, nonce, sys.pcrSelection, model.ContextTagRenew)
	if err != nil {
		t.Fatalf("GetTPMQuote (rinnovo): %v", err)
	}

	if ok := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce, model.ContextTagRenew); !ok {
		t.Fatal("VerifyQuote deve restituire true per un rinnovo con la stessa generazione")
	}

	token, err := sys.verifier.IssueToken(sys.instanceID, 0)
	if err != nil {
		t.Fatalf("IssueToken (rinnovo): %v", err)
	}
	sys.enforcement.UpdateRoutingRules(token)

	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("il routing deve restare consentito dopo un rinnovo riuscito")
	}
}

// TestReplayAttackVieneRilevatoERoutingChiusoSubito è il test più
// importante di questo file: verifica non solo che un replay attack
// venga rilevato (VerifyQuote=false), ma che il routing si chiuda
// IMMEDIATAMENTE, senza dover attendere la scadenza naturale del token —
// esattamente il comportamento che abbiamo verificato a mano nell'ultima
// esecuzione di main.go, ora reso permanente come test automatico.
func TestReplayAttackVieneRilevatoERoutingChiusoSubito(t *testing.T) {
	sys := setupTestSystem(t)
	quote, nonce := bootstrap(t, sys)

	// Precondizione esplicita: prima del replay il routing deve essere
	// aperto. Se questa asserzione fallisse, il resto del test non
	// avrebbe senso (staremmo verificando che qualcosa di già chiuso
	// "resti chiuso", il che non proverebbe nulla sulla revoca immediata).
	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("precondizione non soddisfatta: il routing dovrebbe essere aperto prima del replay")
	}

	// Rigiochiamo DELIBERATAMENTE lo stesso quote/nonce del bootstrap,
	// simulando un attaccante che intercetta e ritrasmette il messaggio.
	if replayOK := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce, model.ContextTagBoot); replayOK {
		t.Fatal("un replay attack non deve mai superare la verifica")
	}

	// Il controllo che conta di più: il routing deve essere già chiuso
	// QUI, nella riga immediatamente successiva a VerifyQuote — non dopo
	// un time.Sleep, non dopo la scadenza del token. Se il canale
	// OnRevoke/Enforcement.Revoke si rompesse in futuro, questa
	// asserzione fallirebbe (mentre BurnRecords più sotto continuerebbe a
	// passare, dato che quel meccanismo non dipende dal canale di
	// notifica) — è quindi il test più mirato possibile su questo
	// specifico meccanismo.
	if sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("dopo un replay rilevato, il routing deve chiudersi IMMEDIATAMENTE (canale di revoca), non restare aperto")
	}

	records := sys.verifier.BurnRecords(sys.instanceID)
	if len(records) != 1 {
		t.Fatalf("atteso esattamente 1 BurnRecord dopo il replay, trovati %d", len(records))
	}
	if records[0].Reason == "" {
		t.Fatal("il BurnRecord deve riportare un motivo non vuoto")
	}

	if _, err := sys.verifier.IssueToken(sys.instanceID, 0); err == nil {
		t.Fatal("IssueToken deve fallire per una generazione bruciata da un replay attack")
	}
}

// TestFailClosedTokenScadutoENonFirmatoCorrettamente verifica la Fase 4
// (comportamento Fail-Closed): un token con ExpiresAt nel passato e firma
// palesemente non valida deve essere rifiutato sia da ValidateToken sia,
// di conseguenza, da IsRoutingAllowed.
func TestFailClosedTokenScadutoENonFirmatoCorrettamente(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys) // porta il sistema in uno stato "con routing valido esistente", per un confronto realistico

	expiredToken := &model.Token{
		InstanceID: sys.instanceID,
		Generation: 0,
		IssuedAt:   time.Now().Add(-2 * time.Minute),
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
		SignatureV: []byte("firma-non-valida-di-test"),
	}

	if sys.enforcement.ValidateToken(expiredToken) {
		t.Fatal("ValidateToken deve rifiutare un token scaduto e con firma non valida")
	}

	sys.enforcement.UpdateRoutingRules(expiredToken)
	if sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("UpdateRoutingRules con un token invalido deve negare il routing, non lasciarlo invariato")
	}
}

// TestFailClosedIstanzaMaiAttestata verifica che un'istanza per cui non è
// mai avvenuto alcun ciclo di attestazione risulti non instradabile per
// default — nessun setup speciale, nessun bootstrap: il default deve
// essere "negato", non "consentito finché non provato il contrario".
func TestFailClosedIstanzaMaiAttestata(t *testing.T) {
	sys := setupTestSystem(t)
	// Notare: NON chiamiamo bootstrap(t, sys) qui — è deliberato, stiamo
	// testando cosa succede PRIMA che qualunque attestazione avvenga.

	if sys.enforcement.IsRoutingAllowed("istanza-completamente-diversa-mai-vista") {
		t.Fatal("un'istanza mai attestata deve risultare non instradabile per default (Fail-Closed)")
	}
}

// TestContextTagSbagliatoRifiutaAncheUnaQuoteTPMRealmenteValida è il
// complemento end-to-end di TestVerifyQuoteRifiutaTagDiContestoNonCorrispondente
// (quel test, in verifier_test.go, usa un AttestationBlob fittizio perché
// il controllo del tag avviene prima della verifica crittografica). Qui
// invece produciamo una quote REALE, firmata da un vero TPM simulato,
// con PCR corretti — e dimostriamo che VIENE COMUNQUE RIFIUTATA se la si
// presenta con un tag diverso da quello con cui è stata prodotta. La
// ragione è più profonda del semplice controllo esplicito su quote.Tag:
// il nonce che il TPM ha effettivamente firmato è vincolato al tag
// ORIGINALE (Renew), quindi anche se qualcuno alterasse il campo Tag nel
// QuotePayload per "farlo sembrare" un Boot, il confronto crittografico
// in server.VerifyAttestation fallirebbe comunque, perché il Verifier
// ricalcolerebbe un nonce vincolato diverso (con tag Boot) da quello
// realmente firmato — due strati di difesa indipendenti, come descritto
// nel commento di verifier.go.
func TestContextTagSbagliatoRifiutaAncheUnaQuoteTPMRealmenteValida(t *testing.T) {
	sys := setupTestSystem(t)

	nonce, err := sys.verifier.GenerateNonce(sys.instanceID)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	// L'Agent produce una quote REALE e valida per un RINNOVO.
	quote, err := sys.agent.GetTPMQuote(0, nonce, sys.pcrSelection, model.ContextTagRenew)
	if err != nil {
		t.Fatalf("GetTPMQuote: %v", err)
	}

	// Il Verifier, però, si aspettava una risposta di BOOTSTRAP per
	// questa challenge (scenario: un bug altrove nel sistema, o un
	// tentativo deliberato di riutilizzo fuori contesto).
	if ok := sys.verifier.VerifyQuote(sys.instanceID, *quote, nonce, model.ContextTagBoot); ok {
		t.Fatal("una quote TPM valida ma con tag di contesto sbagliato non deve mai superare la verifica")
	}
}


// ============================================================================
// FASE 3 — Migrazione Cooperativa: test end-to-end con DUE simulatori TPM
// indipendenti (sorgente e destinazione).
//
// FIX DI BLOCCO (importante): la prima versione di questi test usava
// setupMigrationTarget per aprire il simulatore dell'host target MENTRE
// quello dell'host sorgente (dentro "sys", da setupTestSystem) era ancora
// aperto — stesso identico problema, e stessa causa, già diagnosticati e
// corretti in main.go: aprire un secondo simulatore
// google/go-tpm-tools/simulator mentre un altro è ancora vivo nello
// stesso processo Go si blocca INDEFINITAMENTE (osservato per oltre 2
// ore in una precedente esecuzione di main.go, prima della correzione).
//
// La correzione: ciascun simulatore vive dentro la propria funzione
// helper (runMigrationSourcePhaseForTest, runMigrationTargetPhaseForTest),
// con un "defer" che lo chiude al RITORNO di QUELLA funzione — non
// tramite t.Cleanup, che scatterebbe solo alla fine dell'intero test
// (troppo tardi: il simulatore sorgente deve essere chiuso PRIMA che
// quello target venga aperto, a metà dello stesso test). t.Cleanup resta
// invece perfettamente adatto per setupTestSystem (usato dagli altri
// test di questo file), perché lì un solo simulatore alla volta è mai
// aperto per l'intera durata del test.
// ============================================================================

// migrationSourceResult raccoglie SOLO dati (non risorse TPM ancora
// aperte) da restituire dopo la fase sorgente: il nonce di migrazione,
// unico valore che la fase target deve conoscere per proseguire.
type migrationSourceResult struct {
	nMig []byte
}

// runMigrationSourcePhaseForTest apre il simulatore TPM dell'host
// SORGENTE, esegue un mini-Bootstrap dell'istanza (identico nella forma
// alla Fase 1) e produce/valida Q_src, poi lo CHIUDE (i due "defer"
// scattano al ritorno di QUESTA funzione) prima di restituire il
// controllo al test chiamante — che potrà quindi aprire in sicurezza il
// simulatore dell'host target.
func runMigrationSourcePhaseForTest(t *testing.T, v *verifier.Verifier, e *enforcement.Enforcement, pcrSelection []int, migInstanceID, targetHost string) migrationSourceResult {
	t.Helper()

	srcConn, err := rot.OpenSimulator()
	if err != nil {
		t.Fatalf("rot.OpenSimulator (source): %v", err)
	}
	defer func() { _ = srcConn.Close() }()

	srcRoot, err := rot.NewTPM2RootOfTrust(srcConn)
	if err != nil {
		t.Fatalf("rot.NewTPM2RootOfTrust (source): %v", err)
	}
	defer func() { _ = srcRoot.Close() }()

	srcAgent := agent.NewAgent(migInstanceID, srcRoot)

	if err := srcAgent.ExtendPCR(0, []byte("genuine-bootloader-v1.4")); err != nil {
		t.Fatalf("ExtendPCR(0) source: %v", err)
	}
	if err := srcAgent.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")); err != nil {
		t.Fatalf("ExtendPCR(1) source: %v", err)
	}

	srcPCRs, err := srcRoot.ReadPCRs(pcrSelection)
	if err != nil {
		t.Fatalf("ReadPCRs (source): %v", err)
	}
	srcGolden := combinedPCRDigest(srcPCRs, pcrSelection)
	v.RegisterInstance(migInstanceID, srcRoot.PublicKey(), srcGolden)

	nonce, err := v.GenerateNonce(migInstanceID)
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	quote, err := srcAgent.GetTPMQuote(0, nonce, pcrSelection, model.ContextTagBoot)
	if err != nil {
		t.Fatalf("GetTPMQuote (bootstrap source): %v", err)
	}
	if ok := v.VerifyQuote(migInstanceID, *quote, nonce, model.ContextTagBoot); !ok {
		t.Fatal("il bootstrap dell'istanza di migrazione doveva riuscire")
	}
	token, err := v.IssueToken(migInstanceID, 0)
	if err != nil {
		t.Fatalf("IssueToken (bootstrap source): %v", err)
	}
	e.UpdateRoutingRules(token)

	nMig, err := v.BeginMigration(migInstanceID, targetHost)
	if err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	qSrc, err := srcAgent.GetMigrationSourceQuote(0, nMig, pcrSelection, targetHost)
	if err != nil {
		t.Fatalf("GetMigrationSourceQuote: %v", err)
	}
	if ok := v.ValidateMigrationSource(migInstanceID, *qSrc); !ok {
		t.Fatal("ValidateMigrationSource doveva riuscire per una Q_src genuina")
	}

	return migrationSourceResult{nMig: nMig}
}

// runMigrationTargetPhaseForTest apre il simulatore TPM dell'host
// TARGET — chiamata SOLO dopo che runMigrationSourcePhaseForTest è già
// tornata (e ha quindi già chiuso il proprio simulatore: in Go, senza
// l'uso di goroutine, una funzione gira per intero fino al suo "return"
// prima che l'istruzione successiva nel chiamante venga eseguita, quindi
// l'ordine sequenziale delle due chiamate nei test sotto GARANTISCE che i
// due simulatori non siano mai aperti insieme). Produce Q_dst ed esegue
// CompleteMigration.
//
// Se goldenOverride non è nil, viene usato al posto del Golden
// Measurement realmente misurato sul target: permette a
// TestMigrazioneTargetNonValidaNonComprometteSorgente di simulare un
// mismatch deliberato mantenendo comunque una quote TPM realmente
// firmata (non un dato fittizio) per il resto del flusso.
func runMigrationTargetPhaseForTest(t *testing.T, v *verifier.Verifier, e *enforcement.Enforcement, pcrSelection []int, migInstanceID string, nMig []byte, newGeneration int, goldenOverride []byte) (*model.Token, *model.GenerationLinkCert, bool) {
	t.Helper()

	dstConn, err := rot.OpenSimulator()
	if err != nil {
		t.Fatalf("rot.OpenSimulator (target): %v", err)
	}
	defer func() { _ = dstConn.Close() }()

	dstRoot, err := rot.NewTPM2RootOfTrust(dstConn)
	if err != nil {
		t.Fatalf("rot.NewTPM2RootOfTrust (target): %v", err)
	}
	defer func() { _ = dstRoot.Close() }()

	dstAgent := agent.NewAgent(migInstanceID, dstRoot)

	if err := dstAgent.ExtendPCR(0, []byte("genuine-bootloader-v1.4")); err != nil {
		t.Fatalf("ExtendPCR(0) target: %v", err)
	}
	if err := dstAgent.ExtendPCR(1, []byte("genuine-os-image-sha256:abc123")); err != nil {
		t.Fatalf("ExtendPCR(1) target: %v", err)
	}

	dstGolden := goldenOverride
	if dstGolden == nil {
		dstPCRs, err := dstRoot.ReadPCRs(pcrSelection)
		if err != nil {
			t.Fatalf("ReadPCRs (target): %v", err)
		}
		dstGolden = combinedPCRDigest(dstPCRs, pcrSelection)
	}

	qDst, err := dstAgent.GetTPMQuote(newGeneration, nMig, pcrSelection, model.ContextTagMigrate)
	if err != nil {
		t.Fatalf("GetTPMQuote (target): %v", err)
	}

	return v.CompleteMigration(migInstanceID, newGeneration, *qDst, dstRoot.PublicKey(), dstGolden)
}

// TestMigrazioneCooperativaCompleta è il percorso "felice" end-to-end
// completo: Bootstrap sull'host sorgente, avvio della migrazione,
// validazione di Q_src, boot misurato sull'host target, validazione di
// Q_dst con Atomic Commit, ed esito finale sull'Enforcement.
func TestMigrazioneCooperativaCompleta(t *testing.T) {
	v, err := verifier.New()
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	e := enforcement.New(v.PublicKey())
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})
	pcrSelection := rot.FullPCRSelection()

	const migInstanceID = "vnf-instance-002-migrazione-completa"
	const targetHost = "host-b.datacenter.local"
	const newGeneration = 1

	result := runMigrationSourcePhaseForTest(t, v, e, pcrSelection, migInstanceID, targetHost)

	token, cert, ok := runMigrationTargetPhaseForTest(t, v, e, pcrSelection, migInstanceID, result.nMig, newGeneration, nil)
	if !ok {
		t.Fatal("CompleteMigration doveva avere successo per una Q_dst genuina con Q_src già validata")
	}
	if token == nil || token.Generation != newGeneration {
		t.Fatalf("Token emesso non corretto: %+v", token)
	}
	if cert == nil || cert.OldGeneration != 0 || cert.NewGeneration != newGeneration || cert.TargetHost != targetHost {
		t.Fatalf("GenerationLinkCert non corretto: %+v", cert)
	}

	e.UpdateRoutingRules(token)
	if !e.IsRoutingAllowed(migInstanceID) {
		t.Fatal("il routing deve essere consentito subito dopo una migrazione riuscita")
	}
}

// TestMigrazioneSourceNonValidaBruciaGenerazioneCorrente verifica la
// scelta di design discussa nel commento di ValidateMigrationSource in
// verifier.go: una Q_src non valida (qui: una quote TPM realmente
// firmata, ma per un TargetHost diverso da quello della migrazione
// avviata) brucia la generazione corrente e nega SUBITO il routing.
//
// Questo test usa UN SOLO simulatore TPM (nessun host target coinvolto),
// quindi continua a usare setupTestSystem/bootstrap come gli altri test
// non di migrazione in questo file — nessun rischio del problema di
// blocco descritto sopra.
func TestMigrazioneSourceNonValidaBruciaGenerazioneCorrente(t *testing.T) {
	sys := setupTestSystem(t)
	bootstrap(t, sys)

	if !sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("precondizione non soddisfatta: il routing dovrebbe essere aperto prima del tentativo di migrazione")
	}

	nMig, err := sys.verifier.BeginMigration(sys.instanceID, "host-legittimo")
	if err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	// Q_src REALMENTE valida dal punto di vista TPM, ma dichiara un host
	// di destinazione DIVERSO da quello con cui la migrazione è stata
	// avviata — dimostra che il controllo non è aggirabile nemmeno con
	// una firma autentica, perché targetHost è coperto dalla firma
	// stessa (MigrationSourceBoundNonce).
	qSrc, err := sys.agent.GetMigrationSourceQuote(0, nMig, sys.pcrSelection, "host-non-autorizzato")
	if err != nil {
		t.Fatalf("GetMigrationSourceQuote: %v", err)
	}

	if ok := sys.verifier.ValidateMigrationSource(sys.instanceID, *qSrc); ok {
		t.Fatal("ValidateMigrationSource non deve avere successo con un TargetHost diverso da quello della migrazione avviata")
	}

	if sys.enforcement.IsRoutingAllowed(sys.instanceID) {
		t.Fatal("una Q_src non valida deve bruciare la generazione corrente e negare IMMEDIATAMENTE il routing, tramite lo stesso canale di revoca già usato per il replay attack")
	}
	if records := sys.verifier.BurnRecords(sys.instanceID); len(records) != 1 {
		t.Fatalf("atteso 1 BurnRecord dopo una Q_src non valida, trovati %d", len(records))
	}
}

// TestMigrazioneTargetNonValidaNonComprometteSorgente verifica la scelta
// di design complementare: un fallimento sul lato TARGET (qui: un Golden
// Measurement del target non corrispondente) NON deve avere alcuna
// conseguenza sull'istanza SORGENTE, che aveva già provato sé stessa con
// successo tramite Q_src — la migrazione viene semplicemente abortita.
func TestMigrazioneTargetNonValidaNonComprometteSorgente(t *testing.T) {
	v, err := verifier.New()
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	e := enforcement.New(v.PublicKey())
	v.OnRevoke(func(instanceID string, generation int) {
		e.Revoke(instanceID, generation)
	})
	pcrSelection := rot.FullPCRSelection()

	const migInstanceID = "vnf-instance-002-migrazione-target-fail"
	const targetHost = "host-b.datacenter.local"
	const newGeneration = 1

	result := runMigrationSourcePhaseForTest(t, v, e, pcrSelection, migInstanceID, targetHost)

	if !e.IsRoutingAllowed(migInstanceID) {
		t.Fatal("precondizione non soddisfatta: il routing dovrebbe essere aperto dopo il bootstrap e la validazione di Q_src")
	}

	// Golden Measurement DELIBERATAMENTE sbagliato per il target — simula
	// un mismatch (es. un'immagine software diversa da quella approvata
	// per quella destinazione), indipendentemente da cosa il target abbia
	// realmente misurato.
	wrongGolden := []byte("questo-non-e-un-digest-valido-per-il-target")

	token, cert, ok := runMigrationTargetPhaseForTest(t, v, e, pcrSelection, migInstanceID, result.nMig, newGeneration, wrongGolden)
	if ok || token != nil || cert != nil {
		t.Fatal("CompleteMigration non deve avere successo con un Golden Measurement del target non corrispondente")
	}

	// La generazione SORGENTE (g_0, già validata da Q_src) non deve
	// essere toccata in alcun modo.
	if records := v.BurnRecords(migInstanceID); len(records) != 0 {
		t.Fatalf("un fallimento di Q_dst non deve bruciare alcuna generazione, trovati %d BurnRecords", len(records))
	}
	if !e.IsRoutingAllowed(migInstanceID) {
		t.Fatal("un fallimento di Q_dst non deve interrompere il routing della generazione sorgente, ancora valida")
	}
}
