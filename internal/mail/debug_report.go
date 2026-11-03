package mail

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

const noDCResponseLatencies = "No completed DC response latencies observed."

func (r *TestReport) Value(key, value string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key] = value
}

func (r *TestReport) EnableDebug() {
	if r != nil {
		r.debug = true
	}
}

func (r *TestReport) Trace(_ context.Context, event observe.TraceEvent) {
	if event.Phase != observe.TraceCompleted {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traces = append(r.traces, event)
	r.traceEnds = append(r.traceEnds, time.Now())
}

func (r *TestReport) Inventory(event discovery.InventoryEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inventory = append(r.inventory, event)
}

func (r *TestReport) Measure(step string) func() {
	started := time.Now()
	return func() {
		if r == nil {
			return
		}
		duration := time.Since(started)
		if step == "Credential prompt" {
			r.mu.Lock()
			r.promptDuration += duration
			r.mu.Unlock()
		}
		if !r.debug {
			return
		}
		r.Trace(context.Background(), observe.TraceEvent{Kind: observe.OperationTrace,
			Phase: observe.TraceCompleted, Operation: step, Duration: duration})
	}
}

func (r *TestReport) MarkPasswordPrompted() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passwordPrompted = true
}

func (r *TestReport) dcObservationTable() reportTable {
	dcs := reportTable{header: table.Row{"Discovered DC / service", "Protocol", "Observed reachability", "Avg response", "Replies"}}
	seen := make(map[string]discovery.Endpoint)
	for _, event := range r.inventory {
		for _, group := range [][]discovery.Endpoint{event.Advertised, event.Current.Candidates, event.Retired} {
			for _, endpoint := range group {
				key := endpoint.Address()
				if previous, ok := seen[key]; !ok || len(endpoint.Addresses) > 0 || len(previous.Addresses) == 0 {
					seen[key] = endpoint
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		endpoint := seen[key]
		for _, protocol := range []string{"ldap", "kerberos"} {
			if protocol == "kerberos" && strings.EqualFold(r.values["Cred source"], "sspi") {
				continue
			}
			if row := r.dcObservationRow(key, protocol, endpoint); row != nil {
				dcs.rows = append(dcs.rows, row)
			}
		}
	}
	dnsEndpoints := make(map[string]discovery.Endpoint)
	for _, event := range r.traces {
		if event.Protocol != "dns" || (event.Kind != observe.ExchangeTrace && event.Kind != observe.ConnectionTrace) {
			continue
		}
		_, port, err := net.SplitHostPort(event.Server)
		if err != nil {
			continue
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			continue
		}
		for _, key := range keys {
			endpoint := seen[key]
			endpoint.Port = uint16(number)
			if matchesDCEndpoint(event, endpoint) {
				dnsKey := endpoint.Address()
				previous := dnsEndpoints[dnsKey]
				addresses := previous.Addresses
				for _, address := range endpoint.Addresses {
					if !slices.Contains(addresses, address) {
						addresses = append(addresses, address)
					}
				}
				endpoint.Addresses = addresses
				dnsEndpoints[dnsKey] = endpoint
			}
		}
	}
	dnsKeys := make([]string, 0, len(dnsEndpoints))
	for key := range dnsEndpoints {
		dnsKeys = append(dnsKeys, key)
	}
	sort.Strings(dnsKeys)
	for _, key := range dnsKeys {
		if row := r.dcObservationRow(key, "dns", dnsEndpoints[key]); row != nil {
			dcs.rows = append(dcs.rows, row)
		}
	}
	sort.SliceStable(dcs.rows, func(i, j int) bool {
		left, right := fmt.Sprint(dcs.rows[i][0]), fmt.Sprint(dcs.rows[j][0])
		leftHost, leftPort, _ := net.SplitHostPort(left)
		rightHost, rightPort, _ := net.SplitHostPort(right)
		leftHost, rightHost = strings.ToLower(strings.TrimSuffix(leftHost, ".")), strings.ToLower(strings.TrimSuffix(rightHost, "."))
		if leftHost != rightHost {
			return leftHost < rightHost
		}
		leftMethod, rightMethod := fmt.Sprint(dcs.rows[i][1]), fmt.Sprint(dcs.rows[j][1])
		if leftMethod != rightMethod {
			return leftMethod < rightMethod
		}
		leftNumber, _ := strconv.Atoi(leftPort)
		rightNumber, _ := strconv.Atoi(rightPort)
		return leftNumber < rightNumber
	})
	return dcs
}

func (r *TestReport) stepTimingsTable() reportTable {
	timings := reportTable{header: table.Row{"Step", "Kind", "Scope / parent", "Duration", "Outcome"}}
	for _, event := range r.traces {
		timings.rows = append(timings.rows, table.Row{event.Operation, event.Kind, fmt.Sprintf("%d / %d", event.ID, event.ParentID),
			formatDuration(event.Duration), event.Outcome})
	}
	return timings
}

func (r *TestReport) renderDebug(format reportFormat) string {
	dcs := r.dcObservationTable()
	dcResults := dcs.render(format, r.color, r.values["AD domain"])
	if len(dcs.rows) == 0 {
		dcResults = reportNote(format, noDCResponseLatencies)
	}
	result := r.runtimeBreakdownFormat(format) + "\n" +
		reportNote(format, "DC observations (only endpoints with completed response latency)") + "\n" + dcResults +
		"\n" + reportNote(format, "SSPI KDC endpoints/wire timing: OS-managed / unavailable. DNS rows use observed resolver endpoints matched to discovered DCs.") +
		"\n" + reportNote(format, "Detailed step timings require --verbose.")
	if r.verbose {
		result += "\n" + reportNote(format, "Step timings (nested/concurrent durations overlap; not additive)") + "\n" + r.stepTimingsTable().render(format, r.color, r.values["AD domain"])
	}
	result += "\n" + r.renderTLSDetails(format)
	return result
}

func matchesDCEndpoint(event observe.TraceEvent, endpoint discovery.Endpoint) bool {
	for _, peer := range []string{event.Server, event.Address} {
		host, port, err := net.SplitHostPort(peer)
		if err != nil || port != fmt.Sprint(endpoint.Port) {
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(endpoint.FQDN, ".")) {
			return true
		}
		for _, address := range endpoint.Addresses {
			if host == address.String() {
				return true
			}
		}
	}
	return false
}

func (r *TestReport) dcObservationRow(key, protocol string, endpoint discovery.Endpoint) table.Row {
	var total time.Duration
	replies, failed := 0, 0
	for _, event := range r.traces {
		if event.Kind != observe.ExchangeTrace ||
			event.Protocol != protocol || !matchesDCEndpoint(event, endpoint) {
			continue
		}
		if event.Response {
			replies++
			total += event.Duration
		} else if event.Outcome != observe.Canceled {
			failed++
		}
	}
	if replies == 0 {
		return nil
	}
	status := "Responded"
	if failed > 0 {
		status += fmt.Sprintf("; %d failed attempts", failed)
	}
	return table.Row{key, protocol, status, formatDuration(total / time.Duration(replies)), fmt.Sprint(replies)}
}

const (
	runtimeDNS = iota
	runtimeKerberos
	runtimeLDAP
	runtimeSMTPHandshake
	runtimeSMTPAuth
	runtimeSMTPQuit
	runtimeCleanup
	runtimeHostDiscovery
	runtimeUserLookup
	runtimeCredentialPrompt
	runtimeReportPreparation
	runtimeADSetup
	runtimeOther
)

func runtimeCategory(event observe.TraceEvent) int {
	op := strings.ToLower(event.Operation)
	switch {
	case op == "credential prompt":
		return runtimeCredentialPrompt
	case op == "local user lookup":
		return runtimeUserLookup
	case op == "host/domain discovery":
		return runtimeHostDiscovery
	case op == "report preparation" || op == "report output":
		return runtimeReportPreparation
	case op == "ad identity and canonical mail" || op == "ad client setup" || op == "ad source configuration":
		return runtimeADSetup
	case op == "keytab inspection" || op == "keytab principal selection":
		return runtimeKerberos
	case op == "smtp quit":
		return runtimeSMTPQuit
	case op == "gssapi cleanup" || op == "smtp connection cleanup" || op == "ad credential cleanup":
		return runtimeCleanup
	case event.Protocol == "dns" || strings.Contains(op, "dns"):
		return runtimeDNS
	case event.Protocol == "kerberos" || strings.HasPrefix(op, "credential") ||
		strings.HasPrefix(op, "principal") || op == "service_ticket" || op == "security_context":
		return runtimeKerberos
	case event.Protocol == "ldap" || strings.HasPrefix(op, "ldap") || op == "ad_search" ||
		op == "ad_find_unique" || strings.HasPrefix(op, "ad_race_"):
		return runtimeLDAP
	case op == "smtp gssapi authentication":
		return runtimeSMTPAuth
	case strings.HasPrefix(op, "smtp"):
		return runtimeSMTPHandshake
	default:
		return runtimeOther
	}
}

func (r *TestReport) runtimeBreakdown() string {
	return r.runtimeBreakdownFormat(reportTerminal)
}

func (r *TestReport) runtimeBreakdownTable() reportTable {
	type interval struct {
		start, end time.Time
		category   int
	}
	end := r.snapshotTime()
	points := []time.Time{r.started, end}
	var spans []interval
	for i, event := range r.traces {
		category := runtimeCategory(event)
		if category == runtimeOther {
			continue
		}
		finish := r.traceEnds[i]
		start := finish.Add(-event.Duration)
		if start.Before(r.started) {
			start = r.started
		}
		spans = append(spans, interval{start, finish, category})
		points = append(points, start, finish)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Before(points[j]) })
	durations := make([]time.Duration, runtimeOther+1)
	for i := 1; i < len(points); i++ {
		category := runtimeOther
		for _, span := range spans {
			if !points[i-1].Before(span.start) && !points[i].After(span.end) && span.category < category {
				category = span.category
			}
		}
		durations[category] += points[i].Sub(points[i-1])
	}
	t := reportTable{header: table.Row{"Runtime breakdown", "Elapsed"}}
	labels := []string{"DNS", "Kerberos credentials / tickets", "LDAP", "SMTP handshake", "SMTP auth",
		"SMTP QUIT", "Cleanup", "Host/domain discovery", "Local user lookup", "Credential prompting",
		"Report preparation / output", "AD setup / orchestration", "Other / untracked"}
	order := []int{runtimeCredentialPrompt, runtimeADSetup, runtimeDNS, runtimeKerberos, runtimeLDAP, runtimeSMTPHandshake,
		runtimeSMTPAuth, runtimeSMTPQuit, runtimeCleanup, runtimeHostDiscovery, runtimeUserLookup,
		runtimeReportPreparation, runtimeOther}
	for _, category := range order {
		if durations[category] < 100*time.Microsecond {
			continue
		}
		t.rows = append(t.rows, table.Row{labels[category], formatDuration(durations[category])})
	}
	return t
}

func (r *TestReport) runtimeBreakdownFormat(format reportFormat) string {
	t := r.runtimeBreakdownTable()
	if format == reportPlain {
		t.header = nil
	}
	heading := ""
	if format == reportPlain {
		heading = "Runtime breakdown\n"
	}
	return heading + t.render(format, r.color, r.values["AD domain"]) + "\n" +
		reportNote(format, "Observed wall-time estimate; concurrent work counted once (DNS, then Kerberos, then LDAP precedence). "+
			"Specific operations take precedence over enclosing AD setup/orchestration. Final report rendering/output is outside this snapshot.")
}
