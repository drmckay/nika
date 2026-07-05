from types import SimpleNamespace

from models.sink import Sink
from models.trace import Trace
from vulnerabilities.sql_injection import enrich_sql_injection_evidence


def test_enrich_sql_injection_evidence_keeps_trace_and_labels_query_text():
    sink = Sink(
        rule_id="jdbc-statement-exec-sink",
        file_path="Repo.java",
        line_number=42,
        line_number_end=42,
        code="stmt.executeQuery(sql);",
        metadata={
            "metavars": {
                "$SQL": {
                    "abstract_content": "sql",
                }
            }
        },
    )
    trace = Trace(
        sink_file_path="Repo.java",
        sink_line_number=42,
        source_symbol="com.example.Controller.search:void(java.lang.String)",
    )
    state = SimpleNamespace(sinks=[sink], traces=[trace])

    enrich_sql_injection_evidence(None, None, state)

    assert len(state.traces) == 1
    metadata = state.traces[0].sink.metadata
    assert metadata["sink_kind"] == "sql"
    assert metadata["sink_argument"] == "sql"
    assert metadata["sink_argument_source"] == "opengrep-metavariable"
    assert metadata["sink_argument_role"] == "sql_query_text"
    assert metadata["flow_confidence"] == "method_reachability_only"


def test_enrich_sql_injection_evidence_labels_identifier_fragments():
    sink = Sink(
        rule_id="sql-dynamic-orderby-direct-concat",
        file_path="Repo.java",
        line_number=12,
        line_number_end=12,
        code='stmt.executeQuery("SELECT * FROM users ORDER BY " + column);',
    )
    trace = Trace(
        sink_file_path="Repo.java",
        sink_line_number=12,
        source_symbol="com.example.Controller.search:void(java.lang.String)",
    )
    state = SimpleNamespace(sinks=[sink], traces=[trace])

    enrich_sql_injection_evidence(None, None, state)

    metadata = state.traces[0].sink.metadata
    assert metadata["sink_argument_role"] == "sql_identifier_or_sort_clause"
    assert metadata["query_construction"] == "concatenation"
    assert metadata["flow_confidence"] == "method_reachability_only"
