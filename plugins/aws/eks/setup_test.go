/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package eks

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
)

// The setup template is rendered by the vela CLI; these tests render it the same
// way and check its output against this plugin's own config parsing, allowlist and
// session naming, so the two cannot drift apart.

const (
	templatePath      = "../setup.cue"
	chartTemplatePath = "../../../charts/cluster-gateway/credential-providers/aws.cue"
)

type setupStep struct {
	Title    string   `json:"title"`
	Commands []string `json:"commands"`
}

func renderSetup(t *testing.T, cluster string, params map[string]string) (json.RawMessage, []setupStep, error) {
	t.Helper()
	src, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	v := cuecontext.New().CompileBytes(src)
	if v.Err() != nil {
		t.Fatalf("template does not compile: %v", v.Err())
	}
	v = v.FillPath(cue.ParsePath("context.cluster"), cluster)
	for k, val := range params {
		v = v.FillPath(cue.MakePath(cue.Str("parameter"), cue.Str(k)), val)
	}
	pc := v.LookupPath(cue.ParsePath("providerConfig"))
	if err := pc.Validate(cue.Concrete(true)); err != nil {
		return nil, nil, err
	}
	raw, err := pc.MarshalJSON()
	if err != nil {
		return nil, nil, err
	}
	var steps []setupStep
	if err := v.LookupPath(cue.ParsePath("setup")).Decode(&steps); err != nil {
		return nil, nil, err
	}
	return raw, steps, nil
}

func validParams() map[string]string {
	return map[string]string{
		"region":     "eu-west-1",
		"accountId":  "222222222222",
		"hubRoleArn": "arn:aws:iam::111111111111:role/vela-cluster-gateway",
	}
}

func TestSetupTemplateAgreesWithPlugin(t *testing.T) {
	raw, steps, err := renderSetup(t, "prod-eu", validParams())
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatalf("plugin rejects the rendered provider-config %s: %v", raw, err)
	}
	if cfg.ClusterName != "prod-eu" || cfg.RoleARN != "arn:aws:iam::222222222222:role/vela-prod-eu" {
		t.Errorf("unexpected provider-config %s", raw)
	}

	m := newTestMinter(t, Options{AllowedRoleARNs: []string{"arn:aws:iam::222222222222:role/vela-{cluster}"}})
	if !m.roleAllowed(cfg.RoleARN, "prod-eu") {
		t.Errorf("rendered role %s is not allowed by the documented allowlist entry", cfg.RoleARN)
	}

	trust := between(t, steps[0].Commands[0], "--assume-role-policy-document '", "'")
	var policy struct {
		Statement []struct {
			Principal map[string]string
			Condition map[string]map[string]string
		}
	}
	if err := json.Unmarshal([]byte(trust), &policy); err != nil {
		t.Fatalf("trust policy is not JSON: %v", err)
	}
	if got, want := policy.Statement[0].Condition["StringEquals"]["sts:RoleSessionName"], m.sessionName("prod-eu"); got != want {
		t.Errorf("trust policy pins session %q, plugin assumes the role as %q", got, want)
	}
	if got := policy.Statement[0].Principal["AWS"]; got != "arn:aws:iam::111111111111:role/vela-cluster-gateway" {
		t.Errorf("trust policy principal %q", got)
	}
}

func TestSetupTemplateAccessPolicy(t *testing.T) {
	_, steps, err := renderSetup(t, "prod-eu", validParams())
	if err != nil {
		t.Fatal(err)
	}
	if text := stepsText(steps); strings.Contains(text, "associate-access-policy") || !strings.Contains(text, "with RBAC") {
		t.Errorf("without accessPolicy, want an RBAC step and no association:\n%s", text)
	}

	params := validParams()
	params["accessPolicy"] = "AmazonEKSEditPolicy"
	params["eksCluster"] = "prod-eu-1"
	_, steps, err = renderSetup(t, "prod-eu", params)
	if err != nil {
		t.Fatal(err)
	}
	text := stepsText(steps)
	if !strings.Contains(text, "--cluster-name prod-eu-1 --principal-arn arn:aws:iam::222222222222:role/vela-prod-eu --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy") || strings.Contains(text, "with RBAC") {
		t.Errorf("with accessPolicy, want the association and no RBAC step:\n%s", text)
	}
}

func TestSetupTemplateRejects(t *testing.T) {
	cases := map[string]func(cluster *string, p map[string]string){
		"bad region":          func(_ *string, p map[string]string) { p["region"] = "EU WEST" },
		"missing account":     func(_ *string, p map[string]string) { delete(p, "accountId") },
		"short account":       func(_ *string, p map[string]string) { p["accountId"] = "1234" },
		"hub role not a role": func(_ *string, p map[string]string) { p["hubRoleArn"] = "arn:aws:iam::111111111111:user/x" },
		"role name too long":  func(_ *string, p map[string]string) { p["roleName"] = strings.Repeat("r", 65) },
		"session over 64":     func(c *string, _ map[string]string) { *c = strings.Repeat("c", 50) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cluster, params := "prod-eu", validParams()
			mutate(&cluster, params)
			if _, _, err := renderSetup(t, cluster, params); err == nil {
				t.Error("template accepted invalid input")
			}
		})
	}
}

func TestChartCarriesTheSetupTemplate(t *testing.T) {
	want, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(chartTemplatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from %s; copy the template into the chart", chartTemplatePath, templatePath)
	}
}

func stepsText(steps []setupStep) string {
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(s.Title + "\n" + strings.Join(s.Commands, "\n") + "\n")
	}
	return b.String()
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("missing %q in %q", start, s)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("missing %q after %q", end, start)
	}
	return rest[:j]
}
