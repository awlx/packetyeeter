package metrics

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// variableLabelsPattern extracts the variableLabels list from a
// prometheus.Desc's String() representation, e.g.
// `Desc{fqName: "x", help: "y", constLabels: {}, variableLabels: {a,b,c}}`.
var variableLabelsPattern = regexp.MustCompile(`variableLabels: \{([^}]*)\}`)

func descVariableLabels(t *testing.T, desc *prometheus.Desc) []string {
	t.Helper()
	matches := variableLabelsPattern.FindStringSubmatch(desc.String())
	if matches == nil {
		t.Fatalf("could not find variableLabels in desc string: %s", desc.String())
	}
	raw := matches[1]
	if raw == "" {
		return nil
	}
	labels := regexp.MustCompile(`\s*,\s*`).Split(raw, -1)
	for i, l := range labels {
		labels[i] = regexp.MustCompile(`^"|"$`).ReplaceAllString(l, "")
	}
	return labels
}

func vecLabelNames(t *testing.T, collector prometheus.Collector) []string {
	t.Helper()
	descCh := make(chan *prometheus.Desc, 1)
	collector.Describe(descCh)
	close(descCh)
	desc := <-descCh
	if desc == nil {
		t.Fatalf("expected a description from collector")
	}
	return descVariableLabels(t, desc)
}

// TestCampaignBaselineMetricsShareLabelSet ensures CampaignBaselineMultiplier
// and CampaignBaselineRate expose the same label set (including
// "enough_samples"), so the two metrics can be correlated/joined in
// dashboards and alerting rules (e.g. Prometheus joins on matching labels).
func TestCampaignBaselineMetricsShareLabelSet(t *testing.T) {
	multiplierLabels := vecLabelNames(t, CampaignBaselineMultiplier)
	rateLabels := vecLabelNames(t, CampaignBaselineRate)

	if !reflect.DeepEqual(multiplierLabels, rateLabels) {
		t.Fatalf("expected CampaignBaselineMultiplier and CampaignBaselineRate to share the same label set, got multiplier=%v rate=%v", multiplierLabels, rateLabels)
	}

	for _, want := range []string{"vector", "protocol", "dst_port_bucket", "enough_samples"} {
		found := false
		for _, l := range rateLabels {
			if l == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected CampaignBaselineRate to include label %q, got %v", want, rateLabels)
		}
	}

	// Ensure both metrics can be addressed with the same label values without
	// arity mismatches/panics.
	CampaignBaselineMultiplier.WithLabelValues("udp_flood", "udp", "53", "true").Observe(1.0)
	CampaignBaselineRate.WithLabelValues("udp_flood", "udp", "53", "true").Set(1.0)
}
