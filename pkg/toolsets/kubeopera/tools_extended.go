package kubeopera

import (
	"fmt"
	"net/url"

	"github.com/google/jsonschema-go/jsonschema"
	"k8s.io/utils/ptr"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
)

// ─── Tool: get_alert_rules ────────────────────────────────────────────────────

func (t *Toolset) alertRulesTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_alert_rules",
			Description: "List anomaly alert rules with metric, threshold, severity, and configured auto-heal action (notify/restart_pod/cordon_node/scale_up).",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Alert Rules", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_alert_rules: %w", err)), nil
			}
			u, _ := url.Parse(t.anomalyDetectorURL + "/api/v1/alert-rules")
			if clusterID != "" {
				q := u.Query()
				q.Set("cluster_id", clusterID)
				u.RawQuery = q.Encode()
			}
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_alert_rules: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: execute_runbook ────────────────────────────────────────────────────

func (t *Toolset) executeRunbookTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "execute_runbook",
			Description: "Trigger execution of an automated remediation runbook against an incident. Returns an execution ID to track step-by-step progress.",
			InputSchema: &jsonschema.Schema{
				Type:     "object",
				Required: []string{"incident_id", "runbook_id"},
				Properties: map[string]*jsonschema.Schema{
					"incident_id": {Type: "string", Description: "Incident ID"},
					"runbook_id":  {Type: "string", Description: "Runbook ID to execute"},
					"started_by":  {Type: "string", Description: "Operator email or 'system' (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Execute Runbook", ReadOnlyHint: ptr.To(false), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			incidentID := p.RequiredString("incident_id")
			runbookID := p.RequiredString("runbook_id")
			startedBy := p.OptionalString("started_by", "mcp-agent")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("execute_runbook: %w", err)), nil
			}
			rawURL := fmt.Sprintf("%s/api/v1/incidents/%s/runbooks/%s/execute",
				t.incidentManagerURL, incidentID, runbookID)
			body, err := t.post(params.Context, rawURL, map[string]string{"started_by": startedBy})
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("execute_runbook: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_runbook_execution ──────────────────────────────────────────────

func (t *Toolset) getRunbookExecutionTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_runbook_execution",
			Description: "Get the current status and per-step results of a runbook execution.",
			InputSchema: &jsonschema.Schema{
				Type:     "object",
				Required: []string{"execution_id"},
				Properties: map[string]*jsonschema.Schema{
					"execution_id": {Type: "string", Description: "Runbook execution ID"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Runbook Execution", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			execID := p.RequiredString("execution_id")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_runbook_execution: %w", err)), nil
			}
			body, err := t.get(params.Context, t.incidentManagerURL+"/api/v1/executions/"+execID)
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_runbook_execution: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: generate_post_incident_report ─────────────────────────────────────

func (t *Toolset) generatePIRTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "generate_post_incident_report",
			Description: "Generate an AI-powered post-incident report for a resolved incident. Returns structured summary, root cause, impact, and action items.",
			InputSchema: &jsonschema.Schema{
				Type:     "object",
				Required: []string{"incident_id"},
				Properties: map[string]*jsonschema.Schema{
					"incident_id": {Type: "string", Description: "Incident ID to generate report for"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Post-Incident Report", ReadOnlyHint: ptr.To(false), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			incidentID := p.RequiredString("incident_id")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("generate_post_incident_report: %w", err)), nil
			}
			body, err := t.post(params.Context,
				t.incidentManagerURL+"/api/v1/incidents/"+incidentID+"/pir",
				map[string]string{})
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("generate_post_incident_report: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_node_pools ─────────────────────────────────────────────────────

func (t *Toolset) nodePoolsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_node_pools",
			Description: "List Karpenter NodePools with resource limits, consolidation policy, and node/claim counts.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Node Pools", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.nodesManagerURL+"/api/v1/nodepools")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_node_pools: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_node_claims ────────────────────────────────────────────────────

func (t *Toolset) nodeClaimsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_node_claims",
			Description: "List NodeClaims for a Karpenter NodePool showing phase, instance type, zone, and node name.",
			InputSchema: &jsonschema.Schema{
				Type:     "object",
				Required: []string{"pool_name"},
				Properties: map[string]*jsonschema.Schema{
					"pool_name": {Type: "string", Description: "Karpenter NodePool name"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Node Claims", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			poolName := p.RequiredString("pool_name")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_node_claims: %w", err)), nil
			}
			body, err := t.get(params.Context, t.nodesManagerURL+"/api/v1/nodepools/"+poolName+"/nodeclaims")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_node_claims: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_scheduling_decisions ──────────────────────────────────────────

func (t *Toolset) schedulingDecisionsTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_scheduling_decisions",
			Description: "Get the AI scheduling decision log with workload class, 5-dimension score breakdown, and placement rationale.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"cluster_id": {Type: "string", Description: "Filter by cluster ID (optional)"},
					"limit":      {Type: "integer", Description: "Max results (optional, default 20)"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Scheduling Decisions", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			clusterID := p.OptionalString("cluster_id", "")
			limit := p.OptionalInt64("limit", 20)
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_scheduling_decisions: %w", err)), nil
			}
			u, _ := url.Parse(t.nodesManagerURL + "/api/v1/decisions")
			q := u.Query()
			if clusterID != "" {
				q.Set("cluster_id", clusterID)
			}
			q.Set("limit", fmt.Sprintf("%d", limit))
			u.RawQuery = q.Encode()
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_scheduling_decisions: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_spot_market ────────────────────────────────────────────────────

func (t *Toolset) spotMarketTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_spot_market",
			Description: "Get spot instance pricing, savings vs on-demand, and interruption frequency by zone and instance family.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"region": {Type: "string", Description: "AWS region, e.g. us-east-1 (optional)"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Spot Market", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			region := p.OptionalString("region", "")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_spot_market: %w", err)), nil
			}
			u, _ := url.Parse(t.nodesManagerURL + "/api/v1/spot/market")
			if region != "" {
				q := u.Query()
				q.Set("region", region)
				u.RawQuery = q.Encode()
			}
			body, err := t.get(params.Context, u.String())
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_spot_market: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_consolidation_plan ────────────────────────────────────────────

func (t *Toolset) consolidationPlanTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_consolidation_plan",
			Description: "Get the node consolidation plan showing which nodes can be drained, projected cost savings, and PDB impact analysis.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Consolidation Plan", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.nodesManagerURL+"/api/v1/optimize/plan")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_consolidation_plan: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: get_workload_placement ─────────────────────────────────────────────

func (t *Toolset) workloadPlacementTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "get_workload_placement",
			Description: "Get all workloads with their scheduled node, workload class (latency_sensitive/batch/gpu/stateful/stateless), AI placement score, and rationale.",
			InputSchema: &jsonschema.Schema{Type: "object"},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Workload Placement", ReadOnlyHint: ptr.To(true), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			body, err := t.get(params.Context, t.nodesManagerURL+"/api/v1/workloads/placement")
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("get_workload_placement: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: drain_node_action ──────────────────────────────────────────────────

func (t *Toolset) drainNodeTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "drain_node_action",
			Description: "Gracefully drain a Kubernetes node: cordons it then evicts all non-DaemonSet pods with 30-second grace period.",
			InputSchema: &jsonschema.Schema{
				Type:     "object",
				Required: []string{"node_name"},
				Properties: map[string]*jsonschema.Schema{
					"node_name": {Type: "string", Description: "Kubernetes node name to drain"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Drain Node", ReadOnlyHint: ptr.To(false), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			nodeName := p.RequiredString("node_name")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("drain_node_action: %w", err)), nil
			}
			body, err := t.post(params.Context, t.actionAgentSrvURL+"/api/v1/actions/drain",
				map[string]string{"node_name": nodeName})
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("drain_node_action: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: rollback_deployment ────────────────────────────────────────────────

func (t *Toolset) rollbackDeploymentTool() api.ServerTool {
	return api.ServerTool{
		Tool: api.Tool{
			Name:        "rollback_deployment",
			Description: "Trigger a rollback of a Kubernetes deployment to its previous revision by patching the restartedAt annotation.",
			InputSchema: &jsonschema.Schema{
				Type:     "object",
				Required: []string{"namespace", "deployment_name"},
				Properties: map[string]*jsonschema.Schema{
					"namespace":       {Type: "string", Description: "Kubernetes namespace"},
					"deployment_name": {Type: "string", Description: "Deployment name to roll back"},
				},
			},
			Annotations: api.ToolAnnotations{Title: "KubeOpera: Rollback Deployment", ReadOnlyHint: ptr.To(false), OpenWorldHint: ptr.To(true)},
		},
		Handler: func(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
			p := api.WrapParams(params)
			namespace := p.RequiredString("namespace")
			deploymentName := p.RequiredString("deployment_name")
			if err := p.Err(); err != nil {
				return api.NewToolCallResult("", fmt.Errorf("rollback_deployment: %w", err)), nil
			}
			body, err := t.post(params.Context, t.actionAgentSrvURL+"/api/v1/actions/rollback",
				map[string]string{"namespace": namespace, "deployment_name": deploymentName})
			if err != nil {
				return api.NewToolCallResult("", fmt.Errorf("rollback_deployment: %w", err)), nil
			}
			return api.NewToolCallResult(string(body), nil), nil
		},
	}
}

// ─── Tool: run_node_ops_agent ─────────────────────────────────────────────────

func (t *Toolset) runNodeOpsAgentTool() api.ServerTool {
	return t.agentTool("run_node_ops_agent", "node_ops",
		"Trigger the NodeOps agent to analyse node pool efficiency, scheduling decisions, spot market opportunities, and consolidation plans. Returns a run_id for streaming agent reasoning.")
}
