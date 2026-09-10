package resilience

import (
	"fmt"
	"sync"
	"testing"

	"ra5g/agent"
	"ra5g/model"
)

// stressJob raccoglie tutto il materiale TPM già firmato per una
// singola istanza logica, prodotto durante la fase di pre-generazione
// SEQUENZIALE — nessuno di questi campi viene mai toccato dalla fase
// concorrente successiva, che legge solo dati già pronti.
type stressJob struct {
	instanceID string

	doRenew    bool
	renewNonce []byte
	renewQuote model.QuotePayload

	doMigration bool
	migSrcQuote model.QuotePayload
}

// TestConcurrentMixedOperationsRaceDetector lancia molte goroutine che
// eseguono contemporaneamente un mix di verifiche di rinnovo, tentativi
// di replay (deliberati — devono fallire) e validazioni di migrazione
// sullo STESSO Verifier/Enforcement condivisi.
//
// AGGIORNAMENTO IMPORTANTE: la prima versione di questo test faceva
// firmare le quote (a.GetTPMQuote / a.GetMigrationSourceQuote)
// direttamente DENTRO le goroutine concorrenti, condividendo lo stesso
// simulatore TPM tra tutte — `go test -race` ha correttamente
// individuato una race genuina dentro il simulatore stesso
// (github.com/google/go-tpm-tools/simulator), il cui buffer interno non
// è protetto per scritture concorrenti. Non è un bug di RA5G, ma dello
// scenario di test: nessun deployment reale farebbe condividere UN
// simulatore TPM a 20 istanze logiche diverse contemporaneamente — ogni
// istanza ha il proprio TPM fisico/virtuale.
//
// Corretto separando in due fasi nette: (1) pre-generazione SEQUENZIALE
// di tutto il materiale TPM necessario, un accesso al simulatore alla
// volta — la stessa tecnica già validata più volte in
// test/benchmarks/; (2) fase concorrente che esercita SOLO il Verifier
// (VerifyQuote, ValidateMigrationSource — puro Go, nessuna dipendenza
// da TPM/cgo), che è l'unica cosa che questo test intende davvero
// mettere sotto stress.
//
// Esegui SEMPRE con -race:
//
//	go test ./test/resilience/... -run TestConcurrentMixedOperationsRaceDetector -race -v
func TestConcurrentMixedOperationsRaceDetector(t *testing.T) {
	base, cleanup := newTestRoot(t)
	defer cleanup()

	v, e := newTestVerifierAndEnforcement(t)

	const numWorkers = 20
	const opsPerWorker = 25

	// ------------------------------------------------------------------
	// FASE 1 — pre-generazione SEQUENZIALE. Un solo simulatore, un
	// accesso alla volta: nessuna concorrenza sul TPM, quindi nessun
	// modo di innescare la race di terze parti descritta sopra.
	// ------------------------------------------------------------------
	jobs := make([]stressJob, 0, numWorkers*opsPerWorker)
	for w := 0; w < numWorkers; w++ {
		for i := 0; i < opsPerWorker; i++ {
			instanceID := fmt.Sprintf("stress-%d-%d", w, i)
			a := agent.NewAgent(instanceID, base.root)

			v.RegisterInstance(instanceID, base.root.PublicKey(), base.golden)
			bootNonce, err := v.GenerateNonce(instanceID)
			if err != nil {
				t.Fatalf("GenerateNonce (boot, pre-generazione, %s): %v", instanceID, err)
			}
			bootQuote, err := a.GetTPMQuote(0, bootNonce, base.pcrSelection, model.ContextTagBoot)
			if err != nil {
				t.Fatalf("GetTPMQuote (boot, pre-generazione, %s): %v", instanceID, err)
			}
			if ok := v.VerifyQuote(instanceID, *bootQuote, bootNonce, model.ContextTagBoot); !ok {
				t.Fatalf("bootstrap (pre-generazione) fallito inaspettatamente per %s", instanceID)
			}
			token, err := v.IssueToken(instanceID, 0)
			if err != nil {
				t.Fatalf("IssueToken (pre-generazione, %s): %v", instanceID, err)
			}
			e.UpdateRoutingRules(token)

			job := stressJob{instanceID: instanceID}

			if i%2 == 0 {
				renewNonce, err := v.GenerateNonce(instanceID)
				if err != nil {
					t.Fatalf("GenerateNonce (renew, pre-generazione, %s): %v", instanceID, err)
				}
				renewQuote, err := a.GetTPMQuote(0, renewNonce, base.pcrSelection, model.ContextTagRenew)
				if err != nil {
					t.Fatalf("GetTPMQuote (renew, pre-generazione, %s): %v", instanceID, err)
				}
				job.doRenew = true
				job.renewNonce = renewNonce
				job.renewQuote = *renewQuote
			}

			if i%3 == 0 {
				targetHost := fmt.Sprintf("stress-target-%s", instanceID)
				migNonce, err := v.BeginMigration(instanceID, targetHost)
				if err != nil {
					t.Fatalf("BeginMigration (pre-generazione, %s): %v", instanceID, err)
				}
				migSrcQuote, err := a.GetMigrationSourceQuote(0, migNonce, base.pcrSelection, targetHost)
				if err != nil {
					t.Fatalf("GetMigrationSourceQuote (pre-generazione, %s): %v", instanceID, err)
				}
				job.doMigration = true
				job.migSrcQuote = *migSrcQuote
			}

			jobs = append(jobs, job)
		}
	}

	// ------------------------------------------------------------------
	// FASE 2 — concorrente. Solo operazioni del Verifier, nessuna
	// chiamata al simulatore TPM.
	// ------------------------------------------------------------------
	var wg sync.WaitGroup
	errCh := make(chan error, len(jobs)*2)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * opsPerWorker
			end := start + opsPerWorker
			for _, job := range jobs[start:end] {
				// L'ordine qui è deliberato e importante: la validazione
				// della migrazione va SEMPRE prima del test di rinnovo +
				// replay. Quest'ultimo brucia DELIBERATAMENTE la
				// generazione (è il comportamento corretto di Permanent
				// Revocation, non un bug) — se venisse eseguito prima,
				// qualunque migrazione successiva sulla stessa istanza
				// verrebbe correttamente rifiutata perché la generazione
				// non è più valida, producendo un falso allarme nel
				// test, non nel codice sotto esame. Scoperto per davvero
				// durante lo sviluppo di questo test (vedi
				// README.md per i dettagli).
				if job.doMigration {
					if ok := v.ValidateMigrationSource(job.instanceID, job.migSrcQuote); !ok {
						errCh <- fmt.Errorf("%s: ValidateMigrationSource rifiutata inaspettatamente", job.instanceID)
					}
				}

				if job.doRenew {
					if ok := v.VerifyQuote(job.instanceID, job.renewQuote, job.renewNonce, model.ContextTagRenew); !ok {
						errCh <- fmt.Errorf("%s: rinnovo legittimo rifiutato inaspettatamente", job.instanceID)
						continue
					}
					// Replay immediato della STESSA quote: deve fallire,
					// bruciando deliberatamente la generazione — per
					// questo è sempre l'ULTIMA cosa fatta su una data
					// istanza in questo test.
					if v.VerifyQuote(job.instanceID, job.renewQuote, job.renewNonce, model.ContextTagRenew) {
						errCh <- fmt.Errorf("%s: REPLAY NON RILEVATO — violazione di sicurezza osservata a runtime", job.instanceID)
					}
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	var failures int
	for err := range errCh {
		t.Error(err)
		failures++
	}
	if failures == 0 {
		t.Logf("%d goroutine, %d job pre-generati, nessun errore/race rilevato nella fase concorrente", numWorkers, len(jobs))
	}
}
