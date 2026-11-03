package mail

import (
	"encoding/json"
	"fmt"
	"time"
)

type jsonReportTable struct {
	ID      string     `json:"id"`
	Title   string     `json:"title"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
}

type jsonTestReport struct {
	SchemaVersion int               `json:"schema_version"`
	SnapshotAt    time.Time         `json:"snapshot_at"`
	SnapshotPhase string            `json:"snapshot_phase"`
	Notes         []string          `json:"notes"`
	Tables        []jsonReportTable `json:"tables"`
}

func (r *TestReport) jsonSnapshot() ([]byte, error) {
	snapshot := jsonTestReport{
		SchemaVersion: 1,
		SnapshotAt:    r.snapshotTime().UTC(),
		SnapshotPhase: "after_smtp_authentication_before_data",
		Notes: []string{
			"DATA acceptance, QUIT and final cleanup are not included; consult the local report.",
			"This report contains account names, credential paths and internal topology. Review before sharing.",
		},
	}
	appendTable := func(id, title string, source reportTable) {
		result := jsonReportTable{ID: id, Title: title, Rows: make([][]string, len(source.rows))}
		if source.header == nil {
			result.Columns = []string{"Key", "Value"}
		} else {
			result.Columns = make([]string, len(source.header))
			for i, column := range source.header {
				result.Columns[i] = fmt.Sprint(column)
			}
		}
		for i, row := range source.rows {
			result.Rows[i] = make([]string, len(row))
			for j, cell := range row {
				result.Rows[i][j] = fmt.Sprint(cell)
			}
		}
		snapshot.Tables = append(snapshot.Tables, result)
	}
	appendTable("summary", "Summary", r.summaryTable())
	if issues := r.issuesTable(); len(issues.rows) > 0 {
		appendTable("issues", "Checks / issues", issues)
	}
	if r.debug {
		appendTable("runtime", "Runtime breakdown", r.runtimeBreakdownTable())
		dcs := r.dcObservationTable()
		if len(dcs.rows) > 0 {
			appendTable("dc_observations", "DC observations", dcs)
		} else {
			snapshot.Notes = append(snapshot.Notes, noDCResponseLatencies)
		}
		if r.verbose {
			appendTable("step_timings", "Step timings", r.stepTimingsTable())
		}
		appendTable("tls", "Server TLS certificate / connection", r.tlsDetailsTable())
		appendTable("crypto", "Cryptography (TLS / Kerberos)", r.cryptoTable())
		appendTable("validity", "Validity (TLS certificates / Kerberos)", r.validityTable())
		snapshot.Notes = append(snapshot.Notes,
			"Runtime intervals overlap and are counted once; detailed step durations are not additive.",
			cryptoReportNote,
			validityReportNote,
		)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode testmail JSON report: %w", err)
	}
	return append(data, '\n'), nil
}
