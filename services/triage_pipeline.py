"""
Triage Pipeline — the LangGraph StateGraph definition.

This is the core engine. It defines:
  - TriageState: the shared mutable state passed through every node
  - All graph nodes (normalise → extract → route → burst → react_loop → verdict)
  - Conditional edges for the ReAct loop with budget enforcement
  - The compiled graph entry point

Architecture:
  Phase 1 (deterministic, <2s):
    normalize_alert_node → extract_entities_node → route_tools_node

  Phase 2 (LLM-driven, <60s):
    burst_enrichment_node → agent_think_node ↔ execute_tool_node
    → (budget exhausted or LLM decides done) → generate_verdict_node

State transitions and budget decrement happen inside nodes, not edges.
Edges only route based on sentinel flags in state.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal, Optional

import structlog
from langfuse import observe
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_ollama import ChatOllama
from langgraph.graph import END, StateGraph
from typing_extensions import NotRequired, TypedDict

from app.config import get_settings
from observability.langfuse_client import get_langfuse, get_langfuse_handler, is_enabled
from app.models import (
    AgentThinkResponse,
    AgentThinkToolPlan,
    EscalationDecision,
    ExtractedEntities,
    ImmediateAction,
    MITREAssessment,
    NormalizedAlert,
    Severity,
    ToolCallRecord,
    TriageVerdict,
)
from components.entity_extractor import extract_entities
from services.mitre_router import get_budget, get_tools_for_techniques

logger = structlog.get_logger(__name__)

# Tool names the ReAct THINK step may place in AgentThinkResponse.planned_tools
_REACT_TOOL_NAMES = frozenset(
    {
        "query_splunk",
        "query_crowdstrike",
        "lookup_threat_intel",
        "query_aws",
        "query_cmdb",
        "query_netflow",
        "query_dns_logs",
        "query_backup_systems",
    }
)


def _parse_agent_think_arguments(raw: str) -> dict[str, Any]:
    """Decode JSON object string from AgentThinkToolPlan.arguments for tool execution."""
    if not raw or not str(raw).strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


# ---------------------------------------------------------------------------
# Graph State
# ---------------------------------------------------------------------------


class TriageState(TypedDict):
    """LangGraph state. Optional fields use typing.Optional for TypedDict hints."""

    alert: NormalizedAlert
    entities: Optional[ExtractedEntities]
    technique_ids: list[str]
    severity: str                         # Severity enum value string
    tool_budget: int
    tools_called: list[str]               # names of tools already called
    tool_records: list[ToolCallRecord]
    enrichment_data: dict[str, Any]       # tool_name → compressed summary
    messages: list[Any]                   # LangChain BaseMessage list
    verdict: Optional[TriageVerdict]
    phase: Literal["normalise", "extract", "route", "burst", "react", "verdict", "done"]
    error: Optional[str]
    # Last agent_think structured decision (boolean); routing also requires tool_calls + budget
    tocontinue: NotRequired[bool]


# ---------------------------------------------------------------------------
# Node implementations
# ---------------------------------------------------------------------------


@observe(name="normalise_alert", as_type="span")
async def normalise_alert_node(state: TriageState) -> dict[str, Any]:
    """Validate the incoming alert and set initial severity and phase."""
    alert = state["alert"]
    logger.info("pipeline_normalise", alert_id=alert.alert_id, severity=alert.severity.value)
    return {
        "severity": alert.severity.value,
        "phase": "extract",
        "error": None,
    }


@observe(name="extract_entities", as_type="span")
async def extract_entities_node(state: TriageState) -> dict[str, Any]:
    """Layer 1: Extract typed entities from the alert using the fast LLM."""
    settings = get_settings()
    alert = state["alert"]
    try:
        use_llm = bool(settings.ollama_base_url)
        entities = await extract_entities(alert, use_llm=use_llm)
    except Exception as exc:
        logger.error("entity_extraction_failed", error=str(exc))
        from components.entity_extractor import extract_entities_sync
        entities = extract_entities_sync(alert)

    technique_ids = [t.technique_id for t in entities.techniques]
    # Merge with any technique from the raw alert
    if alert.mitre_technique and alert.mitre_technique not in technique_ids:
        technique_ids.insert(0, alert.mitre_technique)

    logger.info(
        "entities_extracted",
        techniques=technique_ids,
        hosts=[h.hostname for h in entities.hosts],
        iocs_count=len(entities.iocs),
    )
    return {
        "entities": entities,
        "technique_ids": technique_ids or ["T1082"],  # default to System Discovery
        "phase": "route",
    }


@observe(name="route_tools", as_type="span")
async def route_tools_node(state: TriageState) -> dict[str, Any]:
    """Layer 2: Determine tool set and initialise budget based on severity."""
    severity = state["severity"]
    technique_ids = state["technique_ids"]
    budget = get_budget(severity)

    logger.info("routing_complete", techniques=technique_ids, budget=budget)
    return {
        "tool_budget": budget,
        "phase": "burst",
    }


@observe(name="burst_enrichment_node", as_type="span")
async def burst_enrichment_node(state: TriageState) -> dict[str, Any]:
    """
    Fire all routing-table-prescribed tools in parallel.
    Results compressed and stored in enrichment_data.
    Each parallel call consumes 1 from the budget.
    """
    from agents.enrichment_node import run_burst_enrichment, compress_tool_result
    from app.config import get_settings

    settings = get_settings()
    alert = state["alert"]
    entities = state["entities"]
    technique_ids = state["technique_ids"]

    enrichment_data, records = await run_burst_enrichment(
        alert=alert,
        entities=entities,
        technique_ids=technique_ids,
        timeout_seconds=settings.tool_timeout_seconds,
    )

    # Compress all results to strings for the LLM message
    compressed: dict[str, str] = {}
    for tool_name, raw_result in enrichment_data.items():
        compressed[tool_name] = compress_tool_result(tool_name, raw_result)

    tools_called = [r.tool_name for r in records]
    budget_used = len(records)
    new_budget = max(0, state["tool_budget"] - budget_used)

    # Build the initial enrichment summary message
    enrichment_summary = "\n".join(
        f"  • {name}: {summary}" for name, summary in compressed.items()
    )
    initial_message = HumanMessage(
        content=(
            f"ALERT: {alert.title}\n"
            f"SEVERITY: {state['severity']}\n"
            f"ENTITIES: {_format_entities(entities)}\n\n"
            f"INITIAL ENRICHMENT (parallel burst):\n{enrichment_summary}\n\n"
            f"Tool budget remaining: {new_budget}. "
            f"Decide if further investigation is needed."
        )
    )

    logger.info("burst_complete", tools_fired=len(records), budget_remaining=new_budget)
    return {
        "enrichment_data": compressed,
        "tool_records": state.get("tool_records", []) + records,
        "tools_called": state.get("tools_called", []) + tools_called,
        "tool_budget": new_budget,
        "messages": [initial_message],
        "phase": "react",
    }


@observe(name="agent_think", as_type="span")
async def agent_think_node(state: TriageState) -> dict[str, Any]:
    """
    LLM THINK step: structured ``AgentThinkResponse`` with ``tocontinue`` (bool) and optional
    ``planned_tools``. ``should_continue_react`` uses ``tocontinue`` plus ``tool_budget`` and
    non-empty ``tool_calls`` on the emitted ``AIMessage`` to route to execute vs verdict.
    """
    settings = get_settings()
    from prompts.templates import (
        build_triage_prompt,
        get_technique_hint,
        technique_to_class,
    )
    from agents.tools.splunk_tool import query_splunk
    from agents.tools.crowdstrike_tool import query_crowdstrike
    from agents.tools.threat_intel_tool import lookup_threat_intel
    from agents.tools.aws_tool import query_aws
    from agents.tools.cmdb_tool import query_cmdb
    from agents.tools.netflow_tool import query_netflow, query_dns_logs
    from agents.tools.backup_tool import query_backup_systems

    available_tools = [
        query_splunk,
        query_crowdstrike,
        lookup_threat_intel,
        query_aws,
        query_cmdb,
        query_netflow,
        query_dns_logs,
        query_backup_systems,
    ]

    enrichment_summary = "\n".join(
        f"  • {k}: {v}" for k, v in state.get("enrichment_data", {}).items()
    )
    tids = state.get("technique_ids") or []
    tech_hint = get_technique_hint(technique_to_class(tids[0])) if tids else ""
    system_prompt = build_triage_prompt(
        severity=Severity(state["severity"]),
        budget=state["tool_budget"],
        tool_descriptions=_describe_tools(available_tools),
        enrichment_summary=enrichment_summary,
        technique_context=tech_hint,
    )

    messages = [SystemMessage(content=system_prompt)] + state.get("messages", [])
    handler = get_langfuse_handler()
    callbacks_cfg: dict[str, Any] = {"callbacks": [handler]} if handler else {}
    think_out: AgentThinkResponse | None = None

    # --- Attempt 1: Local Ollama ---
    if settings.ollama_base_url:
        try:
            llm = ChatOllama(
                model=settings.deep_model,
                base_url=settings.ollama_base_url,
                num_ctx=settings.ollama_num_ctx,
                keep_alive=settings.ollama_keep_alive,
                temperature=0.1,
            )
            think_out = await llm.with_structured_output(
                AgentThinkResponse,
                method="function_calling",
            ).ainvoke(messages, config=callbacks_cfg)
            logger.info("agent_think_llm", provider="ollama")
        except Exception as exc:
            logger.warning("agent_think_ollama_failed", error=str(exc))

    # --- Attempt 2: OpenAI fallback ---
    if think_out is None and settings.openai_api_key:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.openai_model,
                api_key=settings.openai_api_key,
                temperature=0.1,
            )
            think_out = await llm.with_structured_output(AgentThinkResponse).ainvoke(
                messages, config=callbacks_cfg,
            )
            logger.info("agent_think_llm", provider="openai")
        except Exception as exc:
            logger.error("agent_think_openai_failed", error=str(exc))

    # --- Both failed ---
    if think_out is None:
        logger.error("agent_think_all_llm_failed")
        return {
            "messages": state.get("messages", []) + [
                AIMessage(content="LLM unavailable. Generating verdict from burst enrichment.")
            ],
            "tool_budget": 0,
            "tocontinue": False,
        }

    budget = state["tool_budget"]
    valid_plans: list[AgentThinkToolPlan] = []
    for plan in think_out.planned_tools:
        if plan.name not in _REACT_TOOL_NAMES:
            logger.warning("agent_think_unknown_tool", tool=plan.name)
            continue
        valid_plans.append(plan)
    valid_plans = valid_plans[: max(0, budget)]

    # Model may set tocontinue=True with no valid plans — cannot execute; treat as stop.
    can_execute = bool(think_out.tocontinue) and budget > 0 and len(valid_plans) > 0
    if think_out.tocontinue and budget > 0 and not valid_plans:
        logger.info("agent_think_tocontinue_without_executable_tools")

    tool_calls: list[dict[str, Any]] = []
    if can_execute:
        tool_calls = [
            {
                "name": p.name,
                "args": _parse_agent_think_arguments(p.arguments),
                "id": f"call_{uuid.uuid4().hex[:26]}",
            }
            for p in valid_plans
        ]

    content = think_out.reasoning or (
        "Planning further tool calls." if can_execute else "Stopping ReAct; sufficient context for verdict."
    )
    ai_msg = AIMessage(content=content, tool_calls=tool_calls)

    logger.info(
        "agent_think",
        tocontinue=think_out.tocontinue,
        planned=len(tool_calls),
        budget_remaining=budget,
    )
    return {
        "messages": state.get("messages", []) + [ai_msg],
        "tocontinue": bool(think_out.tocontinue),
    }


@observe(name="execute_tool", as_type="span")
async def execute_tool_node(state: TriageState) -> dict[str, Any]:
    """
    ACT + OBSERVE step: execute every tool the LLM requested in one pass.
    OpenAI may return multiple parallel tool_calls in a single AIMessage and
    requires a ToolMessage for each tool_call_id before the next request.
    """
    from agents.enrichment_node import _execute_single_tool, compress_tool_result
    import asyncio

    messages = state.get("messages", [])
    last_msg = messages[-1] if messages else None

    if not last_msg or not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
        return {"tool_budget": 0}

    tool_calls = last_msg.tool_calls
    logger.info("executing_tools", count=len(tool_calls), budget_before=state["tool_budget"])

    tasks = []
    for tc in tool_calls:
        tasks.append(_execute_single_tool(tc["name"], tc.get("args", {})))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    new_messages = list(messages)
    new_enrichment = {**state.get("enrichment_data", {})}
    new_tools_called = list(state.get("tools_called", []))
    new_records = list(state.get("tool_records", []))
    calls_executed = 0

    for tc, res in zip(tool_calls, results):
        tool_name = tc["name"]
        tool_call_id = tc.get("id", f"call_{calls_executed}")

        if isinstance(res, Exception):
            logger.error("tool_execution_exception", tool=tool_name, error=str(res))
            compressed = f"[{tool_name}] Error: {res}"
            new_messages.append(ToolMessage(content=compressed, tool_call_id=tool_call_id, name=tool_name))
        else:
            _, raw_result, record = res
            compressed = compress_tool_result(tool_name, raw_result)
            new_messages.append(ToolMessage(content=compressed, tool_call_id=tool_call_id, name=tool_name))
            new_enrichment[tool_name] = compressed
            new_records.append(record)

        new_tools_called.append(tool_name)
        calls_executed += 1

    new_budget = state["tool_budget"] - calls_executed

    logger.info("tools_executed", count=calls_executed, budget_remaining=new_budget)
    return {
        "messages": new_messages,
        "tool_budget": new_budget,
        "enrichment_data": new_enrichment,
        "tools_called": new_tools_called,
        "tool_records": new_records,
    }


@observe(name="generate_verdict", as_type="span")
async def generate_verdict_node(state: TriageState) -> dict[str, Any]:
    """
    Final node: LLM generates structured TriageVerdict from all enrichment data.
    Tries local Ollama first; falls back to OpenAI if unavailable.
    """
    settings = get_settings()
    alert = state["alert"]
    entities = state.get("entities")

    enrichment_text = "\n".join(
        f"{k}: {v}" for k, v in state.get("enrichment_data", {}).items()
    ) or "No enrichment data was collected."

    from prompts.templates import build_verdict_prompt, get_technique_hint, technique_to_class

    tids = state.get("technique_ids") or []
    v_hint = get_technique_hint(technique_to_class(tids[0])) if tids else ""

    verdict_prompt = build_verdict_prompt(
        alert_title=alert.title,
        original_severity=state["severity"],
        entities_summary=_format_entities(entities),
        full_enrichment=enrichment_text,
        technique_context=v_hint,
    )

    handler = get_langfuse_handler()
    callbacks_cfg: dict[str, Any] = {"callbacks": [handler]} if handler else {}
    verdict = None

    # --- Attempt 1: Local Ollama ---
    if settings.ollama_base_url:
        try:
            llm = ChatOllama(
                model=settings.deep_model,
                base_url=settings.ollama_base_url,
                num_ctx=settings.ollama_num_ctx,
                keep_alive=settings.ollama_keep_alive,
                temperature=0,
            )
            verdict = await llm.with_structured_output(
                TriageVerdict,
                method="function_calling",
            ).ainvoke(verdict_prompt, config=callbacks_cfg)
            logger.info("verdict_llm", provider="ollama")
        except Exception as exc:
            logger.warning("verdict_ollama_failed", error=str(exc))

    # --- Attempt 2: OpenAI fallback ---
    if verdict is None and settings.openai_api_key:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.openai_model,
                api_key=settings.openai_api_key,
                temperature=0,
            )
            verdict = await llm.with_structured_output(TriageVerdict).ainvoke(
                verdict_prompt, config=callbacks_cfg,
            )
            logger.info("verdict_llm", provider="openai")
        except Exception as exc:
            logger.error("verdict_openai_failed", error=str(exc))

    # --- Both failed → deterministic fallback ---
    if verdict is None:
        verdict = _fallback_verdict(state, alert, "All LLM providers unavailable")
    else:
        verdict.alert_id = alert.alert_id
        verdict.total_tool_calls = len(state.get("tools_called", []))
        verdict.tools_called = list(set(state.get("tools_called", [])))

    logger.info(
        "verdict_generated",
        alert_id=alert.alert_id,
        severity=verdict.severity.value,
        escalation=verdict.escalation.value,
    )
    return {"verdict": verdict, "phase": "done"}


# ---------------------------------------------------------------------------
# Routing functions (conditional edges)
# ---------------------------------------------------------------------------


def should_continue_react(state: TriageState) -> str:
    """
    After agent_think: continue to execute_tool only when the structured flag ``tocontinue``
    is true, there is tool budget left, and the last AIMessage carries non-empty tool_calls.
    """
    if state["tool_budget"] <= 0:
        return "verdict"
    if not state.get("tocontinue", False):
        return "verdict"
    messages = state.get("messages", [])
    if not messages:
        return "verdict"
    last = messages[-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "execute"
    return "verdict"


def after_execute_tool(state: TriageState) -> str:
    """After execute_tool: if budget remains and last message wasn't a tool result, think again."""
    if state["tool_budget"] <= 0:
        return "verdict"
    return "think"


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------


def build_triage_graph() -> Any:
    """Compile and return the LangGraph StateGraph for SOC triage."""
    graph = StateGraph(TriageState)

    graph.add_node("normalise", normalise_alert_node)
    graph.add_node("extract_entities", extract_entities_node)
    graph.add_node("route_tools", route_tools_node)
    graph.add_node("burst_enrichment", burst_enrichment_node)
    graph.add_node("agent_think", agent_think_node)
    graph.add_node("execute_tool", execute_tool_node)
    graph.add_node("generate_verdict", generate_verdict_node)

    graph.set_entry_point("normalise")
    graph.add_edge("normalise", "extract_entities")
    graph.add_edge("extract_entities", "route_tools")
    graph.add_edge("route_tools", "burst_enrichment")
    graph.add_edge("burst_enrichment", "agent_think")

    graph.add_conditional_edges(
        "agent_think",
        should_continue_react,
        {
            "execute": "execute_tool",
            "verdict": "generate_verdict",
        },
    )
    graph.add_conditional_edges(
        "execute_tool",
        after_execute_tool,
        {
            "think": "agent_think",
            "verdict": "generate_verdict",
        },
    )
    graph.add_edge("generate_verdict", END)

    return graph.compile()


# Singleton compiled graph
_compiled_graph = None


def get_triage_graph() -> Any:
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_triage_graph()
    return _compiled_graph


@observe(name="soc_triage_pipeline")
async def run_triage(alert: NormalizedAlert) -> TriageVerdict:
    """
    Primary entry point: takes a NormalizedAlert and returns a TriageVerdict.
    The @observe decorator creates the root Langfuse trace; all child spans
    (entity extraction, burst enrichment, tool calls, verdict) nest beneath it.
    """
    # Attach alert metadata to the trace for filtering in the Langfuse UI
    if is_enabled():
        lf = get_langfuse()
        if lf is not None:
            try:
                lf.update_current_trace(
                    session_id=alert.alert_id,
                    tags=[alert.severity.value, alert.source.value],
                )
            except Exception:
                pass

    graph = get_triage_graph()
    initial_state: TriageState = {
        "alert": alert,
        "entities": None,
        "technique_ids": [],
        "severity": alert.severity.value,
        "tool_budget": 5,   # overwritten in route_tools_node
        "tools_called": [],
        "tool_records": [],
        "enrichment_data": {},
        "messages": [],
        "verdict": None,
        "phase": "normalise",
        "error": None,
    }
    final_state = await graph.ainvoke(initial_state)
    verdict = final_state.get("verdict")
    if verdict is None:
        return _fallback_verdict(final_state, alert, "Graph completed without verdict")
    return verdict


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _format_entities(entities: ExtractedEntities | None) -> str:
    if not entities:
        return "No entities extracted."
    parts = []
    if entities.hosts:
        parts.append(f"Hosts: {', '.join(h.hostname for h in entities.hosts)}")
    if entities.users:
        parts.append(f"Users: {', '.join(u.username for u in entities.users)}")
    if entities.processes:
        parts.append(f"Processes: {', '.join(p.name for p in entities.processes)}")
    if entities.techniques:
        parts.append(f"Techniques: {', '.join(t.technique_id for t in entities.techniques)}")
    if entities.iocs:
        parts.append(f"IOCs: {', '.join(i.value for i in entities.iocs[:5])}")
    return "; ".join(parts) or "No notable entities."


def _describe_tools(tools: list) -> str:
    lines = []
    for t in tools:
        name = getattr(t, "name", str(t))
        desc = (getattr(t, "description", "") or "")[:200]
        lines.append(f"  {name}: {desc}")
    return "\n".join(lines)


def _fallback_verdict(state: TriageState, alert: NormalizedAlert, reason: str) -> TriageVerdict:
    """Construct a minimal verdict when LLM verdict generation fails."""
    return TriageVerdict(
        alert_id=alert.alert_id,
        severity=Severity(state["severity"]),
        severity_justification=f"Fallback verdict — {reason}",
        mitre_assessments=[
            MITREAssessment(
                technique_id=tid,
                technique_name="Unknown",
                tactic="Unknown",
                confidence=0.5,
            )
            for tid in state.get("technique_ids", [])[:3]
        ],
        triage_summary=(
            f"Automated triage for alert: {alert.title}. "
            f"Enrichment collected from {len(state.get('tools_called', []))} sources. "
            f"Manual analyst review required."
        ),
        confirmed_iocs=[],
        immediate_actions=[
            ImmediateAction(priority=1, action="Review alert manually", target=alert.hostname),
            ImmediateAction(priority=2, action="Check enrichment data in pipeline logs"),
            ImmediateAction(priority=3, action="Escalate to senior analyst if uncertain"),
        ],
        escalation=EscalationDecision.MONITOR,
        escalation_rationale="Automated verdict generation failed. Manual review required.",
        total_tool_calls=len(state.get("tools_called", [])),
        tools_called=list(set(state.get("tools_called", []))),
        analyst_confidence=0.3,
        false_positive_probability=0.5,
    )
