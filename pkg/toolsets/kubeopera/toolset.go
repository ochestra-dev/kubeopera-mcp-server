package kubeopera

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"k8s.io/utils/ptr"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/toolsets"
)

func init() {
	toolsets.Register(newToolset())
}

type Toolset struct {
	k8sMonitorURL            string
	securityAPIURL           string
	cicdGatewayURL           string
	kubeOperaAPIURL          string
	anomalyDetectorURL       string
	predictiveScalerURL      string
	incidentManagerURL       string
	observabilityAgentSrvURL  string
	analysisAgentSrvURL       string
	actionAgentSrvURL         string
	feedbackAgentSrvURL       string
	recommendationAgentSrvURL string
	agentRuntimeURL           string
	nodesManagerURL           string
	logGatewayURL             string
	sloManagerURL             string
	apmGatewayURL             string
	tracingGatewayURL         string
	rcaEngineURL              string
	kubeOperaAIURL            string
	httpClient                *http.Client
}

func newToolset() *Toolset {
	return &Toolset{
		k8sMonitorURL:             envOrDefault("K8S_MONITOR_BASE_URL", "http://localhost:8085"),
		securityAPIURL:            envOrDefault("SECURITY_API_BASE_URL", "http://localhost:8086"),
		cicdGatewayURL:            envOrDefault("CICD_GATEWAY_BASE_URL", "http://localhost:8087"),
		kubeOperaAPIURL:           envOrDefault("KUBEOPERA_API_BASE_URL", "http://localhost:8080"),
		anomalyDetectorURL:        envOrDefault("ANOMALY_DETECTOR_BASE_URL", "http://localhost:8088"),
		predictiveScalerURL:       envOrDefault("PREDICTIVE_SCALER_BASE_URL", "http://localhost:8089"),
		incidentManagerURL:        envOrDefault("INCIDENT_MANAGER_BASE_URL", "http://localhost:8090"),
		observabilityAgentSrvURL:  envOrDefault("OBSERVABILITY_AGENT_SRV_BASE_URL", "http://localhost:8092"),
		analysisAgentSrvURL:       envOrDefault("ANALYSIS_AGENT_SRV_BASE_URL", "http://localhost:8093"),
		actionAgentSrvURL:         envOrDefault("ACTION_AGENT_SRV_BASE_URL", "http://localhost:8094"),
		feedbackAgentSrvURL:       envOrDefault("FEEDBACK_AGENT_SRV_BASE_URL", "http://localhost:8095"),
		recommendationAgentSrvURL: envOrDefault("RECOMMENDATION_AGENT_SRV_BASE_URL", "http://localhost:8096"),
		agentRuntimeURL:           envOrDefault("AGENT_RUNTIME_BASE_URL", "http://localhost:8097"),
		nodesManagerURL:           envOrDefault("NODES_MANAGER_BASE_URL", "http://localhost:8098"),
		logGatewayURL:             envOrDefault("LOG_GATEWAY_BASE_URL", "http://localhost:8099"),
		sloManagerURL:             envOrDefault("SLO_MANAGER_BASE_URL", "http://localhost:8100"),
		apmGatewayURL:             envOrDefault("APM_GATEWAY_BASE_URL", "http://localhost:8101"),
		tracingGatewayURL:         envOrDefault("TRACING_GATEWAY_BASE_URL", "http://localhost:8102"),
		rcaEngineURL:              envOrDefault("RCA_ENGINE_BASE_URL", "http://localhost:8103"),
		kubeOperaAIURL:            envOrDefault("KUBEOPERA_AI_BASE_URL", "http://localhost:8104"),
		httpClient:                &http.Client{Timeout: 15 * time.Second},
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func (t *Toolset) GetName() string        { return "kubeopera" }
func (t *Toolset) GetDescription() string { return "KubeOpera AIOps tools: cluster health, costs, CI/CD pipelines, anomaly detection, predictive scaling, incident management, and the full agentic AI layer (observability, analysis, action, feedback, recommendations)." }
func (t *Toolset) GetPrompts() []api.ServerPrompt { return nil }

func (t *Toolset) GetTools(_ api.Openshift) []api.ServerTool {
	return []api.ServerTool{
		// Cluster observability
		t.clusterHealthTool(),
		t.clusterCostTool(),
		t.optimizationReportTool(),
		t.podMetricsTool(),
		t.nodeMetricsTool(),
		t.clusterListTool(),
		t.multiClusterOverviewTool(),
		// Security
		t.securityPostureTool(),
		// CI/CD
		t.pipelineStatusTool(),
		// Anomaly & alerts
		t.anomalyEventsTool(),
		t.alertRulesTool(),
		// Predictive scaling
		t.scalingForecastsTool(),
		// Incidents & runbooks
		t.incidentsTool(),
		t.executeRunbookTool(),
		t.getRunbookExecutionTool(),
		t.generatePIRTool(),
		// Node management
		t.nodePoolsTool(),
		t.nodeClaimsTool(),
		t.schedulingDecisionsTool(),
		t.spotMarketTool(),
		t.consolidationPlanTool(),
		t.workloadPlacementTool(),
		// Write actions
		t.drainNodeTool(),
		t.rollbackDeploymentTool(),
		// Agentic pipeline
		t.agentTelemetryTool(),
		t.analysisResultsTool(),
		t.actionLogTool(),
		t.feedbackOutcomesTool(),
		t.recommendationsTool(),
		// kubeopera-ai continuous optimisation
		t.optimizationStatusTool(),
		t.loadTestAnalysisTool(),
		// Agent runners
		t.runSREAgentTool(),
		t.runSecurityAgentTool(),
		t.runCostAgentTool(),
		t.runIncidentAgentTool(),
		t.runNodeOpsAgentTool(),
		t.runLoadTestAgentTool(),
	}
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

func (t *Toolset) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (t *Toolset) post(ctx context.Context, rawURL string, body map[string]string) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// ─── Tool: get_cluster_health ─────────────────────────────────────────────────

func (t *Toolset) clusterHealthTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_cluster_health",
			Description: "Fetch the real-time cluster health report including overall health score (0-100), node status, pod status, control-plane component health, resource usage percentages, and a list of actionable issues with suggested fixes.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Cluster Health", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.k8sMonitorURL+"/api/health")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_cluster_health: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_cluster_cost ───────────────────────────────────────────────────

func (t *Toolset) clusterCostTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_cluster_cost",
			Description: "Fetch cluster cost data including per-pod, per-node, and per-namespace costs with hourly and monthly breakdowns. Includes CPU, memory, storage, and network cost components.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Cluster Cost", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.k8sMonitorURL+"/api/cost")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_cluster_cost: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_optimization_report ───────────────────────────────────────────

func (t *Toolset) optimizationReportTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_optimization_report",
			Description: "Fetch resource optimization recommendations: idle pods, overprovisioned workloads, potential monthly savings, and unused ConfigMaps/stale resources.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"namespace": {Type: "string", Description: "Filter to a specific namespace (optional)"},
					"view":      {Type: "string", Description: "full | summary | details (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Optimization Report", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			ns := p.OptionalString("namespace", "")
			view := p.OptionalString("view", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_optimization_report: %w", err)), nil
			}
			u, _ := url.Parse(t.k8sMonitorURL + "/api/optimizer")
			q := u.Query()
			if ns != "" {
				q.Set("namespace", ns)
			}
			if view != "" {
				q.Set("view", view)
			}
			u.RawQuery = q.Encode()
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_optimization_report: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_pod_metrics ────────────────────────────────────────────────────

func (t *Toolset) podMetricsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_pod_metrics",
			Description: "Fetch real-time CPU and memory usage metrics for pods, with actual utilization vs resource requests. Optionally filtered by namespace.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"namespace": {Type: "string", Description: "Kubernetes namespace (optional, defaults to all)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Pod Metrics", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			ns := p.OptionalString("namespace", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_pod_metrics: %w", err)), nil
			}
			u, _ := url.Parse(t.k8sMonitorURL + "/api/metrics/pods")
			q := u.Query()
			if ns != "" {
				q.Set("namespace", ns)
			} else {
				q.Set("allNamespaces", "true")
			}
			u.RawQuery = q.Encode()
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_pod_metrics: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_node_metrics ───────────────────────────────────────────────────

func (t *Toolset) nodeMetricsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_node_metrics",
			Description: "Fetch real-time CPU and memory usage metrics for all cluster nodes including capacity, allocatable resources, and current utilization percentages.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Node Metrics", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.k8sMonitorURL+"/api/metrics/nodes")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_node_metrics: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_security_posture ───────────────────────────────────────────────

func (t *Toolset) securityPostureTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_security_posture",
			Description: "Fetch the cluster security posture summary including vulnerability counts, compliance status, risk scores, and security findings.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Cluster identifier for multi-cluster environments (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Security Posture", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_security_posture: %w", err)), nil
			}
			u, _ := url.Parse(t.securityAPIURL + "/api/v1/posture/summary")
			if clusterID != "" {
				q := u.Query()
				q.Set("clusterId", clusterID)
				u.RawQuery = q.Encode()
			}
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_security_posture: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_pipeline_status ────────────────────────────────────────────────

func (t *Toolset) pipelineStatusTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_pipeline_status",
			Description: "Fetch recent CI/CD pipeline runs including pipeline names, branches, commit messages, run statuses, stage breakdowns, durations, and aggregate success rate over the last 7 days.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: `Filter pipeline runs by cluster ID (optional, defaults to "default")`},
					"limit":      {Type: "integer", Description: "Maximum number of recent runs to return per pipeline (optional, default 10)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Pipeline Status", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "default")
			limit := p.OptionalInt64("limit", 10)
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_pipeline_status: %w", err)), nil
			}

			pipelinesURL := fmt.Sprintf("%s/api/v1/pipelines", t.cicdGatewayURL)
			summaryURL := fmt.Sprintf("%s/api/v1/clusters/%s/runs/summary?limit=%d", t.cicdGatewayURL, clusterID, limit)

			type result struct {
				body []byte
				err  error
			}
			pCh := make(chan result, 1)
			sCh := make(chan result, 1)

			go func() {
				b, err := t.get(params.Context, pipelinesURL)
				pCh <- result{b, err}
			}()
			go func() {
				b, err := t.get(params.Context, summaryURL)
				sCh <- result{b, err}
			}()

			pr, sr := <-pCh, <-sCh
			if pr.err != nil && sr.err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_pipeline_status: %w", pr.err)), nil
			}
			combined := fmt.Sprintf(`{"pipelines":%s,"summary":%s}`,
				safeBody(pr.body, pr.err),
				safeBody(sr.body, sr.err),
			)
			return api.NewToolCallResult(combined, nil), nil
		},
	}
}

// ─── Tool: get_cluster_list ───────────────────────────────────────────────────

func (t *Toolset) clusterListTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_cluster_list",
			Description: "Fetch the list of provisioned Kubernetes clusters with health status, node counts (ready vs total), CPU/memory utilization percentages, cloud provider, region, and Kubernetes version.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Cluster List", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.kubeOperaAPIURL+"/api/v1/clusters")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_cluster_list: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_anomaly_events ─────────────────────────────────────────────────

func (t *Toolset) anomalyEventsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_anomaly_events",
			Description: "Fetch recent anomaly events detected by the anomaly-detector. Returns metric name, measured value, Z-score, severity (low/medium/high/critical), namespace, resource name, message, and acknowledgement status. Includes aggregate severity counts.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"severity":   {Type: "string", Description: "Filter by severity: low|medium|high|critical (optional)"},
					"limit":      {Type: "integer", Description: "Maximum number of events to return (optional, default 50)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Anomaly Events", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			severity := p.OptionalString("severity", "")
			limit := p.OptionalInt64("limit", 50)
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_anomaly_events: %w", err)), nil
			}

			u, _ := url.Parse(t.anomalyDetectorURL + "/api/v1/anomalies")
			q := u.Query()
			if clusterID != "" {
				q.Set("cluster_id", clusterID)
			}
			if severity != "" {
				q.Set("severity", severity)
			}
			q.Set("limit", fmt.Sprintf("%d", limit))
			u.RawQuery = q.Encode()

			eventsBody, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_anomaly_events: %w", err)), nil
			}

			statsBody, statsErr := t.get(params.Context, t.anomalyDetectorURL+"/api/v1/anomalies/stats")
			combined := fmt.Sprintf(`{"events":%s,"stats":%s}`,
				string(eventsBody),
				safeBody(statsBody, statsErr),
			)
			return api.NewToolCallResult(combined, nil), nil
		},
	}
}

// ─── Tool: get_scaling_forecasts ──────────────────────────────────────────────

func (t *Toolset) scalingForecastsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_scaling_forecasts",
			Description: "Fetch Holt-Winters predictive scaling forecasts and pending scaling decisions. Returns workload metrics forecasts with confidence bands plus recommendations to scale up or down with current vs recommended replica counts.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"status":     {Type: "string", Description: "Filter decisions by status: pending|approved|applied|rejected (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Scaling Forecasts", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			status := p.OptionalString("status", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_scaling_forecasts: %w", err)), nil
			}

			fu, _ := url.Parse(t.predictiveScalerURL + "/api/v1/forecasts")
			du, _ := url.Parse(t.predictiveScalerURL + "/api/v1/scaling-decisions")
			fq, dq := fu.Query(), du.Query()
			if clusterID != "" {
				fq.Set("cluster_id", clusterID)
				dq.Set("cluster_id", clusterID)
			}
			if status != "" {
				dq.Set("status", status)
			}
			fu.RawQuery = fq.Encode()
			du.RawQuery = dq.Encode()

			type result struct {
				body []byte
				err  error
			}
			fCh := make(chan result, 1)
			dCh := make(chan result, 1)
			go func() { b, err := t.get(params.Context, fu.String()); fCh <- result{b, err} }()
			go func() { b, err := t.get(params.Context, du.String()); dCh <- result{b, err} }()
			fr, dr := <-fCh, <-dCh

			combined := fmt.Sprintf(`{"forecasts":%s,"scaling_decisions":%s}`,
				safeBody(fr.body, fr.err),
				safeBody(dr.body, dr.err),
			)
			return api.NewToolCallResult(combined, nil), nil
		},
	}
}

// ─── Tool: get_incidents ──────────────────────────────────────────────────────

func (t *Toolset) incidentsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_incidents",
			Description: "Fetch active and recent incidents from the incident-manager. Returns incident title, severity, status (open/investigating/mitigating/resolved), category, affected service, MTTR, and aggregate SRE metrics (open count, critical count, average MTTR).",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"status":     {Type: "string", Description: "Filter by status: open|investigating|mitigating|resolved (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Incidents", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			status := p.OptionalString("status", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_incidents: %w", err)), nil
			}

			iu, _ := url.Parse(t.incidentManagerURL + "/api/v1/incidents")
			q := iu.Query()
			if clusterID != "" {
				q.Set("cluster_id", clusterID)
			}
			if status != "" {
				q.Set("status", status)
			}
			iu.RawQuery = q.Encode()

			type result struct {
				body []byte
				err  error
			}
			iCh := make(chan result, 1)
			mCh := make(chan result, 1)
			go func() { b, err := t.get(params.Context, iu.String()); iCh <- result{b, err} }()
			go func() { b, err := t.get(params.Context, t.incidentManagerURL+"/api/v1/incidents/metrics"); mCh <- result{b, err} }()
			ir, mr := <-iCh, <-mCh

			if ir.err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_incidents: %w", ir.err)), nil
			}
			combined := fmt.Sprintf(`{"incidents":%s,"metrics":%s}`,
				string(ir.body),
				safeBody(mr.body, mr.err),
			)
			return api.NewToolCallResult(combined, nil), nil
		},
	}
}

// ─── Tool: get_multi_cluster_overview ─────────────────────────────────────────

func (t *Toolset) multiClusterOverviewTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_multi_cluster_overview",
			Description: "Fetch an aggregated health, cost, and incident overview across all provisioned clusters. Returns per-cluster health score, node counts, CPU/memory usage, and a cross-cluster summary with total nodes and resource utilization.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Multi-Cluster Overview", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			type result struct {
				body []byte
				err  error
			}
			cCh := make(chan result, 1)
			hCh := make(chan result, 1)
			go func() { b, err := t.get(params.Context, t.kubeOperaAPIURL+"/api/v1/clusters"); cCh <- result{b, err} }()
			go func() { b, err := t.get(params.Context, t.k8sMonitorURL+"/api/health"); hCh <- result{b, err} }()
			cr, hr := <-cCh, <-hCh

			combined := fmt.Sprintf(`{"clusters":%s,"health":%s}`,
				safeBody(cr.body, cr.err),
				safeBody(hr.body, hr.err),
			)
			return api.NewToolCallResult(combined, nil), nil
		},
	}
}

// ─── Tool: get_agent_telemetry ────────────────────────────────────────────────

func (t *Toolset) agentTelemetryTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_agent_telemetry",
			Description: "Fetch the latest telemetry snapshot collected by observability-agent-srv. Returns aggregated cluster metrics: CPU, memory, health score, security score, pipeline success rate, crash loop count, active incidents, and estimated cost.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Agent Telemetry", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_agent_telemetry: %w", err)), nil
			}
			u, _ := url.Parse(t.observabilityAgentSrvURL + "/api/v1/telemetry/latest")
			if clusterID != "" {
				q := u.Query()
				q.Set("cluster_id", clusterID)
				u.RawQuery = q.Encode()
			}
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_agent_telemetry: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_analysis_results ───────────────────────────────────────────────

func (t *Toolset) analysisResultsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_analysis_results",
			Description: "Fetch the latest statistical analysis results from analysis-agent-srv's AI core. Returns detected anomalies with Z-scores, generated Kubernetes remediation decisions (scale/restart/cordon/notify), health score, risk score (0-100), and a human-readable summary.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Analysis Results", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_analysis_results: %w", err)), nil
			}
			u, _ := url.Parse(t.analysisAgentSrvURL + "/api/v1/results/latest")
			if clusterID != "" {
				q := u.Query()
				q.Set("cluster_id", clusterID)
				u.RawQuery = q.Encode()
			}
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_analysis_results: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_action_log ─────────────────────────────────────────────────────

func (t *Toolset) actionLogTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_action_log",
			Description: "Fetch the log of automated remediation actions executed by action-agent-srv. Returns action type (scale_deployment/restart_pod/cordon_node/notify), target resource name, namespace, status (pending/executing/success/failed), error details, and timestamps.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"limit":      {Type: "integer", Description: "Maximum number of actions to return (optional, default 50)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Action Log", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			limit := p.OptionalInt64("limit", 50)
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_action_log: %w", err)), nil
			}
			u, _ := url.Parse(t.actionAgentSrvURL + "/api/v1/actions")
			q := u.Query()
			if clusterID != "" {
				q.Set("cluster_id", clusterID)
			}
			q.Set("limit", fmt.Sprintf("%d", limit))
			u.RawQuery = q.Encode()
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_action_log: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_feedback_outcomes ─────────────────────────────────────────────

func (t *Toolset) feedbackOutcomesTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_feedback_outcomes",
			Description: "Fetch closed-loop feedback outcomes from feedback-agent-srv. Shows whether each automated remediation action was effective, which triggers reinforcement (lower threshold) or correction (raise threshold) signals back to analysis-agent-srv.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"limit":      {Type: "integer", Description: "Maximum number of outcomes to return (optional, default 50)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: Feedback Outcomes", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			limit := p.OptionalInt64("limit", 50)
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_feedback_outcomes: %w", err)), nil
			}
			u, _ := url.Parse(t.feedbackAgentSrvURL + "/api/v1/outcomes")
			q := u.Query()
			if clusterID != "" {
				q.Set("cluster_id", clusterID)
			}
			q.Set("limit", fmt.Sprintf("%d", limit))
			u.RawQuery = q.Encode()
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_feedback_outcomes: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_recommendations ───────────────────────────────────────────────

func (t *Toolset) recommendationsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_recommendations",
			Description: "Fetch AI-generated SRE recommendations from recommendation-agent-srv (powered by Claude). Returns categorized recommendations (security/cost/performance/reliability) with priority (low/medium/high/critical), description, expected impact, and the specific action to take.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"limit":      {Type: "integer", Description: "Maximum number of recommendations to return (optional, default 50)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: AI Recommendations", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			limit := p.OptionalInt64("limit", 50)
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_recommendations: %w", err)), nil
			}
			u, _ := url.Parse(t.recommendationAgentSrvURL + "/api/v1/recommendations")
			q := u.Query()
			if clusterID != "" {
				q.Set("cluster_id", clusterID)
			}
			q.Set("limit", fmt.Sprintf("%d", limit))
			u.RawQuery = q.Encode()
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_recommendations: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: run_sre_agent ──────────────────────────────────────────────────────

func (t *Toolset) runSREAgentTool() api.ServerTool {
	return t.agentTool("run_sre_agent", "sre_orchestrator",
		"Trigger the SRE Orchestrator agent to investigate cluster health, correlate anomalies, and produce a prioritised remediation plan. Returns a run_id you can use to stream agent reasoning.")
}

func (t *Toolset) runSecurityAgentTool() api.ServerTool {
	return t.agentTool("run_security_agent", "security_auditor",
		"Trigger the Security Auditor agent to analyse the security posture, identify vulnerabilities and misconfigurations, and recommend fixes. Returns a run_id for streaming.")
}

func (t *Toolset) runCostAgentTool() api.ServerTool {
	return t.agentTool("run_cost_agent", "cost_optimizer",
		"Trigger the Cost Optimizer agent to identify waste, right-sizing opportunities, and savings across clusters. Returns a run_id for streaming.")
}

func (t *Toolset) runIncidentAgentTool() api.ServerTool {
	return t.agentTool("run_incident_agent", "incident_responder",
		"Trigger the Incident Responder agent to triage active incidents, correlate signals, and produce a step-by-step remediation runbook. Returns a run_id for streaming.")
}

func (t *Toolset) agentTool(name, agentType, description string) api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        name,
			Description: description,
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Cluster to investigate (optional)"},
					"prompt":     {Type: "string", Description: "Custom investigation prompt (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{
				Title: "KubeOpera: " + agentType, ReadOnlyHint: ptr.To(false), OpenWorldHint: ptr.To(true),
			},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			prompt := p.OptionalString("prompt", "")
			if p.Err() != nil {
				return nil, p.Err()
			}
			if prompt == "" {
				prompt = "Analyse the current state and provide detailed findings and recommendations."
			}
			body, err := t.post(params.Context, t.agentRuntimeURL+"/api/v1/runs", map[string]string{
				"agent_type": agentType,
				"cluster_id": clusterID,
				"prompt":     prompt,
			})
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("%s: %w", name, err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Utility ─────────────────────────────────────────────────────────────────

func safeBody(body []byte, err error) string {
	if err != nil || len(body) == 0 {
		return `null`
	}
	return string(body)
}
