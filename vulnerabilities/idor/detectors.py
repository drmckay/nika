import re

_PATH_VAR_RE = re.compile(r"\{\s*([A-Za-z_$][\w$]*)\s*(?::[^}]*)?\}")

_PATH_PARAM_ANNOTATIONS = ("PathVariable", "PathParam")
_QUERY_PARAM_ANNOTATIONS = ("RequestParam", "QueryParam")


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _matches(name: str, normalized_identifiers: set[str]) -> bool:
    candidate = normalize(name)
    if not candidate:
        return False
    return any(
        candidate == identifier or candidate.endswith(identifier)
        for identifier in normalized_identifiers
        if identifier
    )


def extract_path_variables(path: str) -> list[str]:
    if not path:
        return []
    return _PATH_VAR_RE.findall(path)


def _bound_names_from_code(code: str, annotation_names: tuple[str, ...]) -> list[str]:
    if not code:
        return []

    pattern = re.compile(
        r"@(?:" + "|".join(annotation_names) + r")\b\s*(\([^)]*\))?\s*([^,)]*)"
    )
    names: list[str] = []
    for match in pattern.finditer(code):
        paren, remainder = match.group(1) or "", match.group(2) or ""
        quoted = re.search(r'"([^"]+)"', paren)
        if quoted:
            names.append(quoted.group(1))
        # The parameter's own name is the last identifier token before the comma/paren.
        words = re.findall(r"[A-Za-z_$][\w$]*", remainder)
        if words:
            names.append(words[-1])
    return names


def find_idor_identifier(
    path: str | None,
    code: str | None,
    identifiers: list[str],
    *,
    include_query_params: bool = False,
    scan_code: bool = True,
) -> tuple[str | None, str | None]:
    normalized_identifiers = {normalize(identifier) for identifier in identifiers if identifier}
    if not normalized_identifiers:
        return None, None

    for variable in extract_path_variables(path):
        if _matches(variable, normalized_identifiers):
            return variable, "path-template"

    if scan_code:
        annotation_names = _PATH_PARAM_ANNOTATIONS
        if include_query_params:
            annotation_names = annotation_names + _QUERY_PARAM_ANNOTATIONS
        for name in _bound_names_from_code(code, annotation_names):
            if _matches(name, normalized_identifiers):
                kind = "path-parameter"
                return name, kind

    return None, None
