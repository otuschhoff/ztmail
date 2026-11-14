package mail

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
	// SDK callback slices belong to the invocation, not to the report.
	event = cloneInventoryEvent(event)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inventory = append(r.inventory, event)
}

func cloneInventoryEvent(event discovery.InventoryEvent) discovery.InventoryEvent {
	event.Advertised = cloneInventoryEndpoints(event.Advertised)
	event.Current.Candidates = cloneInventoryEndpoints(event.Current.Candidates)
	event.Retired = cloneInventoryEndpoints(event.Retired)
	return event
}

func cloneInventoryEndpoints(endpoints []discovery.Endpoint) []discovery.Endpoint {
	endpoints = slices.Clone(endpoints)
	for i := range endpoints {
		endpoints[i].Addresses = slices.Clone(endpoints[i].Addresses)
	}
	return endpoints
}

func appendDCAddresses(endpoint *discovery.Endpoint, addresses []netip.Addr) {
	for _, address := range addresses {
		if !slices.Contains(endpoint.Addresses, address) {
			endpoint.Addresses = append(endpoint.Addresses, address)
		}
	}
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
	// Rows represent lifetime completed-response evidence, not current
	// availability. Match identities against all historical addresses without
	// selecting generation or health metadata; owned raw events preserve both.
	for _, event := range r.inventory {
		for _, group := range [][]discovery.Endpoint{event.Advertised, event.Current.Candidates, event.Retired} {
			for _, endpoint := range group {
				key := endpoint.Address()
				previous, ok := seen[key]
				if !ok {
					previous = discovery.Endpoint{FQDN: endpoint.FQDN, Port: endpoint.Port}
				}
				appendDCAddresses(&previous, endpoint.Addresses)
				seen[key] = previous
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
				previous.FQDN, previous.Port = endpoint.FQDN, endpoint.Port
				appendDCAddresses(&previous, endpoint.Addresses)
				dnsEndpoints[dnsKey] = previous
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
	return r.renderDebugTables(format, r.debugTables())
}

func (r *TestReport) renderDebugTables(format reportFormat, tables reportTables) string {
	dcs := tables.dcs
	dcResults := dcs.render(format, r.color, r.values["AD domain"])
	if len(dcs.rows) == 0 {
		dcResults = reportNote(format, noDCResponseLatencies)
	}
	var result strings.Builder
	result.WriteString(r.runtimeBreakdownTableFormat(format, tables.runtime))
	result.WriteByte('\n')
	result.WriteString(reportNote(format, "DC observations (only endpoints with completed response latency)"))
	result.WriteByte('\n')
	result.WriteString(dcResults)
	result.WriteByte('\n')
	result.WriteString(reportNote(format, "SSPI KDC endpoints/wire timing: OS-managed / unavailable. DNS rows use observed resolver endpoints matched to discovered DCs."))
	result.WriteByte('\n')
	result.WriteString(reportNote(format, "Detailed step timings require --verbose."))
	if r.verbose {
		result.WriteByte('\n')
		result.WriteString(reportNote(format, "Step timings (nested/concurrent durations overlap; not additive)"))
		result.WriteByte('\n')
		result.WriteString(tables.timings.render(format, r.color, r.values["AD domain"]))
	}
	result.WriteByte('\n')
	result.WriteString(r.renderTLSDetailsTables(format, tables))
	return result.String()
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
	case op == "smtp gssapi authentication" || op == "smtp external authentication":
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

func (r *TestReport) runtimeDurations() [runtimeOther + 1]time.Duration {
	type point struct {
		at              time.Time
		category, delta int
	}
	var durations [runtimeOther + 1]time.Duration
	end := r.snapshotTime()
	tracked := 0
	var categories []int
	for i, event := range r.traces {
		category := runtimeCategory(event)
		if category != runtimeOther {
			if categories == nil {
				categories = make([]int, len(r.traces))
			}
			// Zero marks untracked entries; offset IDs so DNS remains distinct.
			categories[i] = category + 1
			tracked++
		}
	}
	if tracked == 0 {
		start := r.started
		if end.Before(start) {
			start, end = end, start
		}
		durations[runtimeOther] = end.Sub(start)
		return durations
	}
	points := make([]point, 0, 2+2*tracked)
	points = append(points, point{at: r.started}, point{at: end})
	for i, stored := range categories {
		if stored == 0 {
			continue
		}
		category := stored - 1
		event := r.traces[i]
		finish := r.traceEnds[i]
		start := finish.Add(-event.Duration)
		if start.Before(r.started) {
			start = r.started
		}
		delta := 0
		// Empty/reversed spans retain timeline boundaries without covering an interval.
		if start.Before(finish) {
			delta = 1
		}
		points = append(points, point{start, category, delta}, point{finish, category, -delta})
	}
	sort.Slice(points, func(i, j int) bool { return points[i].at.Before(points[j].at) })
	var active [runtimeOther + 1]int
	previous := points[0].at
	for i := 0; i < len(points); {
		current := points[i].at
		category := runtimeOther
		for candidate := 0; candidate < runtimeOther; candidate++ {
			if active[candidate] > 0 {
				category = candidate
				break
			}
		}
		durations[category] += current.Sub(previous)
		for i < len(points) && points[i].at.Equal(current) {
			active[points[i].category] += points[i].delta
			i++
		}
		previous = current
	}
	return durations
}

func (r *TestReport) runtimeBreakdownTable() reportTable {
	durations := r.runtimeDurations()
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
	return r.runtimeBreakdownTableFormat(format, r.runtimeBreakdownTable())
}

func (r *TestReport) runtimeBreakdownTableFormat(format reportFormat, t reportTable) string {
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
