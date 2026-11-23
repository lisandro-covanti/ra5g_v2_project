// Questo file dichiara "package verifier" — LO STESSO package di
// verifier.go, non "verifier_test". Per questo si dice test "white-box"
// (o "internal"): oltre a IssueToken/VerifyQuote/Revoke (esportati, con
// iniziale maiuscola), potremmo qui accedere anche a dettagli PRIVATI del
// package come burnLocked o il campo v.onRevoke — non lo facciamo quasi
// mai in questi test (restiamo il più possibile sull'API pubblica, per
// non legare i test a dettagli interni che potrebbero cambiare), ma è
// bene sapere che la possibilità esiste con questo tipo di package.
//
// NESSUNO di questi test apre una connessione TPM: testano solo la logica
// di business del Verifier che non dipende dalla tecnologia di
// attestazione (hook di revoca, registro dei burn, guardia sui token) —
// per questo sono rapidissimi da eseguire (millisecondi, non decine di
// millisecondi come i test che coinvolgono il simulatore TPM in
// main_test.go).
package verifier

import (
	"testing"
	"time"

	"ra5g/model"
)

// TestRevokeManualeNotificaGliHookRegistrati verifica il meccanismo di
// notifica introdotto per colmare il gap "Revoca Immediata Routing":
// quando Revoke() viene chiamato, ogni hook registrato con OnRevoke deve
// essere eseguito ESATTAMENTE una volta, con instanceID e generation
// corretti.
func TestRevokeManualeNotificaGliHookRegistrati(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	const generation = 0

	// hookChiamato/hookInstanceID/hookGeneration sono variabili "catturate"
	// dalla closure passata a OnRevoke qui sotto — la funzione anonima
	// "vede" queste variabili dell'ambiente circostante e le modifica
	// quando viene eseguita, permettendoci di verificarle DOPO la
	// chiamata a Revoke.
	var hookChiamato bool
	var hookInstanceID string
	var hookGeneration int

	v.OnRevoke(func(instanceID string, generation int) {
		hookChiamato = true
		hookInstanceID = instanceID
		hookGeneration = generation
	})

	v.Revoke(instanceID, generation, "test manuale")

	if !hookChiamato {
		t.Fatal("l'hook registrato con OnRevoke non è stato chiamato da Revoke")
	}
	if hookInstanceID != instanceID {
		t.Fatalf("hook chiamato con instanceID=%q, atteso %q", hookInstanceID, instanceID)
	}
	if hookGeneration != generation {
		t.Fatalf("hook chiamato con generation=%d, atteso %d", hookGeneration, generation)
	}
}

// TestRevokeNotificaTuttiGliHookRegistrati verifica che, se sono
// registrati PIÙ hook (scenario realistico: in futuro potremmo avere sia
// l'Enforcement sia un sistema di logging/audit iscritti), vengano
// chiamati TUTTI, non solo il primo.
func TestRevokeNotificaTuttiGliHookRegistrati(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var contatore int
	v.OnRevoke(func(string, int) { contatore++ })
	v.OnRevoke(func(string, int) { contatore++ })
	v.OnRevoke(func(string, int) { contatore++ })

	v.Revoke("test-instance", 0, "test")

	if contatore != 3 {
		t.Fatalf("attesi 3 hook eseguiti, eseguiti %d", contatore)
	}
}

// TestIssueTokenFallisceDopoRevoke verifica la guardia già presente in
// IssueToken: una volta che una generazione è stata bruciata (qui tramite
// una revoca manuale, per non dipendere dal TPM), IssueToken deve
// rifiutarsi di emettere un nuovo token per quella stessa generazione.
func TestIssueTokenFallisceDopoRevoke(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	v.Revoke(instanceID, 0, "generazione compromessa")

	if _, err := v.IssueToken(instanceID, 0); err == nil {
		t.Fatal("IssueToken doveva restituire un errore per una generazione bruciata, ha restituito nil")
	}
}

// TestIssueTokenFunzionaPerGenerazioneNonBruciata è il "controllo di
// sanità" complementare al test precedente: verifica che la guardia sulla
// generazione bruciata non blocchi anche generazioni DIVERSE, non
// coinvolte dalla revoca — altrimenti un bug nella guardia potrebbe
// passare inosservato (es. se isBurnedLocked confrontasse solo
// l'instanceID e ignorasse la generation).
func TestIssueTokenFunzionaPerGenerazioneNonBruciata(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	v.Revoke(instanceID, 0, "generazione 0 compromessa")

	// La generazione 1 della STESSA istanza non è mai stata bruciata:
	// IssueToken deve poterla emettere senza problemi.
	if _, err := v.IssueToken(instanceID, 1); err != nil {
		t.Fatalf("IssueToken sulla generazione 1 (mai bruciata) doveva riuscire, errore: %v", err)
	}
}

// TestVerifyQuoteRifiutaIstanzaMaiRegistrata verifica il primissimo
// controllo di VerifyQuote (istanza sconosciuta al Verifier) — un caso
// che non richiede alcuna quote TPM valida per essere testato, perché il
// rifiuto avviene prima ancora di guardare il contenuto della quote.
func TestVerifyQuoteRifiutaIstanzaMaiRegistrata(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Un QuotePayload vuoto va benissimo qui: il Verifier deve fermarsi
	// al controllo di registrazione, prima ancora di provare a
	// deserializzare AttestationBlob (che sarebbe comunque vuoto/non
	// valido). Se questo test fallisse "in profondità" invece che subito,
	// sarebbe un segnale che l'ordine dei controlli in verifyQuoteLocked
	// è stato alterato.
	emptyQuote := model.QuotePayload{}

	if ok := v.VerifyQuote("istanza-mai-vista", emptyQuote, []byte("nonce"), model.ContextTagBoot); ok {
		t.Fatal("VerifyQuote non deve mai avere successo per un'istanza mai registrata")
	}

	// Nessun BurnRecord deve essere stato creato: un'istanza sconosciuta
	// non è "un attacco da bruciare", è semplicemente fuori dal perimetro
	// di fiducia — non c'è nulla da revocare per un'istanza che non è mai
	// stata ammessa in primo luogo.
	if records := v.BurnRecords("istanza-mai-vista"); len(records) != 0 {
		t.Fatalf("attesi 0 BurnRecords per un'istanza mai registrata, trovati %d", len(records))
	}
}

// TestVerifyQuoteRifiutaTagDiContestoNonCorrispondente verifica il
// meccanismo di context-binding introdotto per impedire che una quote
// prodotta per un'operazione (es. rinnovo) venga accettata come risposta
// a una challenge di un'operazione DIVERSA (es. bootstrap). Il controllo
// avviene prima ancora di deserializzare l'AttestationBlob, quindi questo
// test non ha bisogno di una quote TPM realmente valida — un QuotePayload
// con solo Tag e Generation impostati basta a esercitarlo.
func TestVerifyQuoteRifiutaTagDiContestoNonCorrispondente(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const instanceID = "test-instance"
	// RegisterInstance con chiave pubblica e golden measurement fittizi:
	// il controllo del tag avviene PRIMA che questi valori vengano mai
	// usati, quindi il loro contenuto non ha importanza per questo test.
	v.RegisterInstance(instanceID, nil, []byte("golden-fittizio"))

	quote := model.QuotePayload{
		InstanceID: instanceID,
		Generation: 0,
		Tag:        model.ContextTagBoot, // la quote dichiara di essere una risposta di Bootstrap...
	}

	// ...ma il Verifier si aspettava una risposta di Renew (es. perché
	// questa era la challenge emessa per un rinnovo di lease).
	if ok := v.VerifyQuote(instanceID, quote, []byte("nonce"), model.ContextTagRenew); ok {
		t.Fatal("VerifyQuote deve rifiutare una quote il cui Tag non corrisponde al contesto atteso")
	}

	records := v.BurnRecords(instanceID)
	if len(records) != 1 {
		t.Fatalf("atteso esattamente 1 BurnRecord per il mismatch di context tag, trovati %d", len(records))
	}
}

// ============================================================================
// FASE 3 — Migrazione Cooperativa: test unitari sui percorsi che NON
// richiedono un TPM reale (early-exit prima della deserializzazione
// dell'AttestationBlob, esattamente come per il context tag sopra). Il
// percorso end-to-end completo, con quote TPM realmente valide da
// entrambe le istanze, è coperto da main_test.go.
// ============================================================================

// setLiveForTest imposta direttamente lo stato "live" di un'istanza,
// bypassando l'intero ciclo Bootstrap/VerifyQuote — lecito qui perché
// questo file è white-box (stesso package di verifier.go, vedi il
// commento in cima al file) e serve solo a preparare lo stato necessario
// per testare BeginMigration/CompleteMigration senza il costo di un vero
// TPM per ogni singolo test.
func setLiveForTest(v *Verifier, instanceID string, generation int) {
	v.live[instanceID] = &liveEntry{Generation: generation, ExpiresAt: time.Now().Add(time.Hour)}
}

// TestBeginMigrationRifiutaIstanzaNonLive verifica che non si possa
// avviare una migrazione per un'istanza che non risulta attualmente live
// per nessuna generazione — non avrebbe senso "migrare" qualcosa che il
// Verifier non considera nemmeno in esecuzione.
func TestBeginMigrationRifiutaIstanzaNonLive(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := v.BeginMigration("istanza-mai-avviata", "host-b"); err == nil {
		t.Fatal("BeginMigration doveva restituire un errore per un'istanza non live, ha restituito nil")
	}
}

// TestBeginMigrationHaSuccessoPerIstanzaLive verifica il percorso base:
// un'istanza live ottiene un nonce di migrazione non vuoto.
func TestBeginMigrationHaSuccessoPerIstanzaLive(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	setLiveForTest(v, "vnf-1", 0)

	nonce, err := v.BeginMigration("vnf-1", "host-b")
	if err != nil {
		t.Fatalf("BeginMigration: errore inatteso %v", err)
	}
	if len(nonce) == 0 {
		t.Fatal("BeginMigration doveva restituire un nonce non vuoto")
	}
}

// TestValidateMigrationSourceRifiutaSenzaBeginMigration verifica che
// ValidateMigrationSource rifiuti una quote se non è mai stata avviata
// alcuna migrazione (nessuna chiamata a BeginMigration) per l'istanza —
// e che, non essendo necessariamente un attacco (più probabile una
// chiamata fuori sequenza), NON generi un BurnRecord.
func TestValidateMigrationSourceRifiutaSenzaBeginMigration(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))

	quote := model.QuotePayload{InstanceID: "vnf-1", Generation: 0, Tag: model.ContextTagMigrate}
	if ok := v.ValidateMigrationSource("vnf-1", quote); ok {
		t.Fatal("ValidateMigrationSource non deve avere successo senza una migrazione avviata con BeginMigration")
	}
	if records := v.BurnRecords("vnf-1"); len(records) != 0 {
		t.Fatalf("attesi 0 BurnRecords senza una migrazione avviata, trovati %d", len(records))
	}
}

// TestValidateMigrationSourceRifiutaTargetHostDiverso verifica che una
// quote che dichiara un TargetHost diverso da quello della migrazione
// avviata con BeginMigration venga rifiutata E bruci la generazione
// corrente (qui SÌ è un evento sospetto: la migrazione è stata avviata
// verso un host specifico, la quote ne dichiara un altro).
func TestValidateMigrationSourceRifiutaTargetHostDiverso(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 0)

	nonce, err := v.BeginMigration("vnf-1", "host-legittimo")
	if err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	quote := model.QuotePayload{
		InstanceID: "vnf-1",
		Generation: 0,
		Tag:        model.ContextTagMigrate,
		Nonce:      nonce,
		TargetHost: "host-diverso", // non corrisponde a quello di BeginMigration
	}
	if ok := v.ValidateMigrationSource("vnf-1", quote); ok {
		t.Fatal("ValidateMigrationSource non deve avere successo con un TargetHost diverso da quello della migrazione avviata")
	}
	if records := v.BurnRecords("vnf-1"); len(records) != 1 {
		t.Fatalf("atteso 1 BurnRecord per il mismatch di TargetHost, trovati %d", len(records))
	}
}

// TestValidateMigrationSourceRifiutaGenerazioneDiversa verifica lo stesso
// principio per il campo Generation: una quote riferita a una generazione
// diversa da quella live al momento di BeginMigration viene rifiutata e
// brucia la generazione dichiarata nella quote.
func TestValidateMigrationSourceRifiutaGenerazioneDiversa(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 2) // l'istanza è live alla generazione 2

	nonce, err := v.BeginMigration("vnf-1", "host-b")
	if err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	quote := model.QuotePayload{
		InstanceID: "vnf-1",
		Generation: 0, // non corrisponde alla generazione live (2)
		Tag:        model.ContextTagMigrate,
		Nonce:      nonce,
		TargetHost: "host-b",
	}
	if ok := v.ValidateMigrationSource("vnf-1", quote); ok {
		t.Fatal("ValidateMigrationSource non deve avere successo con una Generation diversa da quella live al momento della richiesta")
	}
}

// TestValidateMigrationSourceRifiutaNonceDiverso verifica lo stesso
// principio per il nonce: una quote con un nonce diverso da n_mig
// (es. rigiocando un vecchio nonce di Bootstrap/Renew) viene rifiutata.
func TestValidateMigrationSourceRifiutaNonceDiverso(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 0)

	if _, err := v.BeginMigration("vnf-1", "host-b"); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	quote := model.QuotePayload{
		InstanceID: "vnf-1",
		Generation: 0,
		Tag:        model.ContextTagMigrate,
		Nonce:      []byte("nonce-completamente-diverso"),
		TargetHost: "host-b",
	}
	if ok := v.ValidateMigrationSource("vnf-1", quote); ok {
		t.Fatal("ValidateMigrationSource non deve avere successo con un nonce diverso da n_mig")
	}
}

// TestCompleteMigrationRifiutaSenzaMigrazionePendente verifica che
// CompleteMigration rifiuti se non esiste alcuna migrazione avviata per
// l'istanza (nessuna chiamata a BeginMigration).
func TestCompleteMigrationRifiutaSenzaMigrazionePendente(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	quote := model.QuotePayload{InstanceID: "vnf-1", Generation: 1, Tag: model.ContextTagMigrate}
	token, cert, ok := v.CompleteMigration("vnf-1", 1, quote, nil, []byte("golden"))
	if ok || token != nil || cert != nil {
		t.Fatal("CompleteMigration non deve avere successo senza una migrazione avviata con BeginMigration")
	}
}

// TestCompleteMigrationRifiutaSenzaSourceValidato è IL test che verifica
// la proprietà "Atomic Migration (Dual-Sided Authorization)" del
// documento di analisi originale: anche con una migrazione avviata
// (BeginMigration chiamato), CompleteMigration deve rifiutarsi di
// procedere se ValidateMigrationSource non è MAI stata chiamata con
// successo — non deve esistere alcun percorso che ammetta una nuova
// generazione senza il consenso provato dell'istanza uscente.
func TestCompleteMigrationRifiutaSenzaSourceValidato(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 0)

	if _, err := v.BeginMigration("vnf-1", "host-b"); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	// Deliberatamente NESSUNA chiamata a ValidateMigrationSource qui.

	quote := model.QuotePayload{InstanceID: "vnf-1", Generation: 1, Tag: model.ContextTagMigrate}
	token, cert, ok := v.CompleteMigration("vnf-1", 1, quote, nil, []byte("golden-target"))
	if ok || token != nil || cert != nil {
		t.Fatal("CompleteMigration non deve MAI avere successo senza che Q_src sia stata validata da ValidateMigrationSource")
	}
}

// TestCompleteMigrationRifiutaGenerazioneNonCrescente verifica che una
// migrazione debba SEMPRE produrre una generazione strettamente
// maggiore di quella uscente — a differenza di un rinnovo, dove la
// stessa generazione è legittima.
func TestCompleteMigrationRifiutaGenerazioneNonCrescente(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 3)

	// Forziamo manualmente SourceValidated=true per isolare SOLO il
	// controllo sulla generazione, senza dipendere da una vera quote TPM.
	if _, err := v.BeginMigration("vnf-1", "host-b"); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	v.pendingMigrations["vnf-1"].SourceValidated = true

	quote := model.QuotePayload{InstanceID: "vnf-1", Generation: 3, Tag: model.ContextTagMigrate}
	// newGeneration=3, uguale a OldGeneration=3: non è una migrazione
	// valida (deve essere strettamente maggiore).
	token, cert, ok := v.CompleteMigration("vnf-1", 3, quote, nil, []byte("golden-target"))
	if ok || token != nil || cert != nil {
		t.Fatal("CompleteMigration non deve avere successo con newGeneration <= oldGeneration")
	}
}

// I due test seguenti verificano il TTL sulle migrazioni pendenti
// (DefaultMigrationTTL), introdotto per risolvere la lacuna già
// documentata in docs/05-roadmap.md: una migrazione avviata con
// BeginMigration e mai portata a termine lasciava lo stato interno del
// Verifier "appeso" indefinitamente. Entrambi i test retrodatano
// manualmente pending.ExpiresAt (lecito qui: file white-box, stesso
// package di verifier.go) invece di attendere realmente 2 minuti — un
// vero test di timeout che dormisse per la durata reale del TTL
// sarebbe corretto ma renderebbe la suite inutilmente lenta.

// TestValidateMigrationSourceRifiutaMigrazionePendenteScaduta verifica
// che una migrazione pendente scaduta venga trattata come "mai avviata":
// ValidateMigrationSource la rifiuta SENZA bruciare alcuna generazione
// (la scadenza per timeout non è, di per sé, un evento sospetto), e lo
// stato pendente viene ripulito.
func TestValidateMigrationSourceRifiutaMigrazionePendenteScaduta(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 0)

	nonce, err := v.BeginMigration("vnf-1", "host-b")
	if err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	// Retrodatiamo la scadenza: la migrazione risulta già scaduta.
	v.pendingMigrations["vnf-1"].ExpiresAt = time.Now().Add(-time.Second)

	quote := model.QuotePayload{
		InstanceID: "vnf-1",
		Generation: 0,
		Tag:        model.ContextTagMigrate,
		Nonce:      nonce,
		TargetHost: "host-b",
	}
	if ok := v.ValidateMigrationSource("vnf-1", quote); ok {
		t.Fatal("ValidateMigrationSource non deve avere successo per una migrazione pendente scaduta")
	}
	if records := v.BurnRecords("vnf-1"); len(records) != 0 {
		t.Fatalf("una migrazione scaduta per timeout non deve bruciare alcuna generazione, trovati %d BurnRecords", len(records))
	}

	// Conferma che lo stato pendente sia stato ripulito: un secondo
	// tentativo (senza una nuova BeginMigration) deve fallire come "nessuna
	// migrazione avviata", non più come "scaduta" (perché l'entry non
	// esiste più affatto).
	if _, hasPending := v.pendingMigrations["vnf-1"]; hasPending {
		t.Fatal("lo stato di migrazione pendente scaduto doveva essere rimosso da pendingMigrations")
	}
}

// TestCompleteMigrationRifiutaMigrazionePendenteScaduta verifica lo
// stesso principio per CompleteMigration: anche con SourceValidated=true,
// una migrazione scaduta viene rifiutata e ripulita, senza toccare la
// generazione sorgente.
func TestCompleteMigrationRifiutaMigrazionePendenteScaduta(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.RegisterInstance("vnf-1", nil, []byte("golden"))
	setLiveForTest(v, "vnf-1", 0)

	if _, err := v.BeginMigration("vnf-1", "host-b"); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	v.pendingMigrations["vnf-1"].SourceValidated = true
	v.pendingMigrations["vnf-1"].ExpiresAt = time.Now().Add(-time.Second)

	quote := model.QuotePayload{InstanceID: "vnf-1", Generation: 1, Tag: model.ContextTagMigrate}
	token, cert, ok := v.CompleteMigration("vnf-1", 1, quote, nil, []byte("golden-target"))
	if ok || token != nil || cert != nil {
		t.Fatal("CompleteMigration non deve avere successo per una migrazione pendente scaduta")
	}
	if _, hasPending := v.pendingMigrations["vnf-1"]; hasPending {
		t.Fatal("lo stato di migrazione pendente scaduto doveva essere rimosso da pendingMigrations")
	}
}
