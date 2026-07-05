from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


def _normalize_path(path):
    return (path or "").replace("\\", "/")


def _matching_sink(sinks, trace):
    normalized = _normalize_path(getattr(trace, "sink_file_path", ""))
    matches = [
        sink
        for sink in (sinks or [])
        if sink.line_number == trace.sink_line_number
        and (
            _normalize_path(sink.file_path) == normalized
            or normalized.endswith(_normalize_path(sink.file_path))
            or _normalize_path(sink.file_path).endswith(normalized)
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _metavar_content(metadata: dict, *names: str) -> str:
    metavars = metadata.get("metavars")
    if not isinstance(metavars, dict):
        return ""
    for name in names:
        value = metavars.get(name)
        if isinstance(value, dict) and value.get("abstract_content"):
            return str(value.get("abstract_content")).strip()
    return ""


def _sink_argument(sink) -> str:
    metadata = getattr(sink, "metadata", None) or {}
    return _metavar_content(
        metadata,
        "$SQL",
        "$HQL",
        "$QUERY",
        "$INPUT",
        "$VAR",
        "$COLUMN",
        "$TABLE",
        "$CLAUSE",
        "$VALUE",
    )


def _sink_argument_role(rule_id: str, code: str) -> str:
    text = f"{rule_id} {code}".lower()
    if any(term in text for term in ("orderby", "groupby", "order by", "group by")):
        return "sql_identifier_or_sort_clause"
    if any(term in text for term in ("table", "column", "join ")):
        return "sql_identifier"
    if any(term in text for term in ("having", " limit ", " offset ", " set ")):
        return "sql_fragment"
    if any(term in text for term in ("setparameter", ".bind(", "bindby")):
        return "sql_bind_parameter"
    return "sql_query_text"


def _query_construction(rule_id: str, code: str) -> str:
    text = f"{rule_id} {code}".lower()
    if "string.format" in text or "messageformat" in text or "format" in text:
        return "format_string"
    if "stringbuilder" in text or "append(" in text:
        return "string_builder"
    if "concat" in text or " + " in code:
        return "concatenation"
    return "unknown"


def _sql_metadata(sink) -> dict:
    metadata = dict(getattr(sink, "metadata", None) or {})
    rule_id = getattr(sink, "rule_id", None) or metadata.get("rule_id") or ""
    code = getattr(sink, "code", "") or ""
    metadata.setdefault("sink_kind", "sql")
    sink_argument = metadata.get("sink_argument") or _sink_argument(sink)
    if sink_argument:
        metadata.setdefault("sink_argument", sink_argument)
        metadata.setdefault("sink_argument_source", "opengrep-metavariable")
    metadata.setdefault("sink_argument_role", _sink_argument_role(rule_id, code))
    metadata.setdefault("query_construction", _query_construction(rule_id, code))
    metadata.setdefault("flow_confidence", "method_reachability_only")
    return metadata


def enrich_sql_injection_evidence(vulnerability, context, state):
    enriched = []
    for trace in getattr(state, "traces", None) or []:
        sink = getattr(trace, "sink", None) or _matching_sink(
            getattr(state, "sinks", None), trace
        )
        if sink is None:
            enriched.append(trace)
            continue
        enriched_sink = sink.model_copy(update={"metadata": _sql_metadata(sink)})
        enriched.append(trace.model_copy(update={"sink": enriched_sink}))

    state.traces = enriched
    return state


class SqlInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "sql_injection"
    title = "SQL Injection"
    description = (
        "SQL Injection vulnerability allows attackers to interfere with the "
        "queries that an application makes to its database."
    )
    supported_languages = ["java"]
    required_engine_roles = ["sink_finder", "source_finder", "dataflow_analyzer"]
    source_types = ["remote_input"]
    prompt_kind = "trace"
    stages = [
        match_rule_sinks,
        discover_sources,
        run_dataflow,
        enrich_sql_injection_evidence,
        review_traces_with_llm,
        finalize_findings,
    ]
    optional_stages = [review_traces_with_llm]
    review_mode = "optional"
    system_prompt = (
        "Review this trace for SQL injection risk. Treat dynamic SQL built from "
        "user-controlled input as suspicious, but consider parameterized queries "
        "and safe bound parameters non-vulnerable. If the code path is unclear or "
        "uses a custom query builder, return NEED_MANUAL_REVIEW. Evidence fields "
        "such as sink argument role, query construction, and flow confidence are "
        "hints for triage, not proof that attacker input reached executable SQL."
    )
    human_prompt = (
        "Analyze this SQL injection trace and decide whether attacker-controlled "
        "input can reach executable SQL without safe parameterization."
    )
    fallback_explanation = (
        "Trace reached the SQL sink. LLM review is not configured, so the finding "
        "is being surfaced for manual triage."
    )
    fallback_remediation = (
        "Verify whether user-controlled input reaches the query without "
        "parameterization."
    )
    fallback_code_fix = (
        "Use parameterized queries or prepared statements for user-controlled "
        "values."
    )
