from vulnerabilities.open_redirect import _flow_to_sink, _request_inputs


def test_request_inputs_extracts_spring_request_param():
    signature = (
        "public void redirect(@RequestParam String next, "
        "HttpServletResponse response)"
    )

    assert _request_inputs(signature, "") == {"next": "@RequestParam"}


def test_flow_to_sink_marks_direct_request_param_redirect():
    body = """
    public void redirect(@RequestParam String next, HttpServletResponse response) {
        response.sendRedirect(next);
    }
    """
    metadata = _flow_to_sink(
        body,
        "public void redirect(@RequestParam String next, HttpServletResponse response)",
        "response.sendRedirect(next);",
        "next",
    )

    assert metadata["request_controlled"] is True
    assert metadata["source_param"] == "next"
    assert metadata["source_kind"] == "@RequestParam"
    assert metadata["sink_argument"] == "next"
    assert "@RequestParam next -> response.sendRedirect(next);" in metadata["flow_summary"]


def test_flow_to_sink_drops_constant_redirect_target():
    body = """
    public void redirect(@RequestParam String next, HttpServletResponse response) {
        response.sendRedirect("/home");
    }
    """
    metadata = _flow_to_sink(
        body,
        "public void redirect(@RequestParam String next, HttpServletResponse response)",
        'response.sendRedirect("/home");',
        '"/home"',
    )

    assert metadata["request_controlled"] is False
    assert metadata["flow_confidence"] == "not_request_controlled"


def test_flow_to_sink_follows_local_assignment():
    body = """
    public void redirect(@RequestParam String next, HttpServletResponse response) {
        String target = "/go?next=" + next;
        response.sendRedirect(target);
    }
    """
    metadata = _flow_to_sink(
        body,
        "public void redirect(@RequestParam String next, HttpServletResponse response)",
        "response.sendRedirect(target);",
        "target",
    )

    assert metadata["request_controlled"] is True
    assert metadata["flow_confidence"] == "local-derived"
    assert 'target = "/go?next=" + next' in metadata["flow_summary"]


def test_flow_to_sink_includes_validation_evidence():
    body = """
    public void redirect(@RequestParam String next, HttpServletResponse response) {
        if (!next.startsWith("/")) {
            throw new RuntimeException("blocked");
        }
        response.sendRedirect(next);
    }
    """
    metadata = _flow_to_sink(
        body,
        "public void redirect(@RequestParam String next, HttpServletResponse response)",
        "response.sendRedirect(next);",
        "next",
    )

    assert "startsWith" in metadata["validation_evidence"]
