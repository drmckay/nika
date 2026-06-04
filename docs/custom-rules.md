## What is Taint Analysis?

Before we start creating custom rules, let’s quickly understand taint analysis.

Taint analysis tracks how **untrusted data** flows through an application and determines whether it reaches a **security-sensitive operation**.

* **Source** → The point where data enters the application.
* **Sink** → A sensitive operation that may become vulnerable if it receives untrusted data.

### Example

````md
```java
@Path("/execute")
public Response run(@QueryParam("cmd") String cmd) {   // Source
    Runtime.getRuntime().exec(cmd);                   // Sink
    return Response.ok().build();
}
```
````

In this example:

* `cmd` → Source (user-controlled input)
* `Runtime.exec()` → Sink (command execution)

If untrusted data reaches a sink without proper validation, it may result in a vulnerability.

> NIKA uses configurable **Sources** and **Sinks** for taint analysis.
> You can view and customize the supported source definitions in `crtConfig.yml` or `native-crtConfig.yml`.

### Supported Source Types

NIKA identifies externally controlled inputs using configurable **Source Definitions**.
By default, the following framework annotations are treated as sources for taint analysis:

```yaml
sources:
  annotations:
    - "@RequestMapping"
    - "@GetMapping"
    - "@PostMapping"
    - "@PutMapping"
    - "@DeleteMapping"
    - "@PatchMapping"
    - "@Path"
```

## Supported Vulnerability Rules

Currently, NIKA supports detection for the following vulnerability categories.

| Detection Type | Vulnerabilities                                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------------------------------- |
| Taint Analysis | Code Injection, Command Injection, Deserialization, Path Traversal, SQL Injection, SSRF, Template Injection, XXE |
| Sink Analysis  | Cryptographic Failures, Sensitive Logging, Unsafe Reflection                                                     |

**Detection Types**

* **Taint Analysis** → Tracks data flow from **sources → sinks** to identify exploitable paths.
* **Sink Analysis** → Detects direct usage of insecure APIs or dangerous patterns without requiring data flow tracking.

## Vulnerability Definitions in Nika

Let's take an example of how a vulnerability is defined in Nika.
For this example, we'll use **Command Injection**.

### Define a Source

Sources are independent of vulnerabilities and define **where untrusted data enters the application**.

For example, `@Path` can be configured as a source to identify API entry points.

As mentioned earlier, source definitions are configured in:

> `crtConfig.yml` or `native-crtConfig.yml` → `sources → annotations`

Example:

````md
```yaml
sources:
  annotations:
    - "@RequestMapping"
    - "@GetMapping"
    - "@Path"
```
````

---

### Define a Sink

Nika uses OpenGrep to define sinks.

A sink represents a **security-sensitive operation** that becomes vulnerable if attacker-controlled input reaches it.

Steps:

1. Navigate to `rules/Java/command_injection`
2. Locate the existing sink definitions written in OpenGrep YAML format
3. Add a new sink definition if required

For example, to detect `new ProcessBuilder()`:

````md
```yaml
rules:
  - id: java-command-injection-process-builder
    mode: taint
    languages:
      - java
    severity: ERROR
    message: >-
      Potential Command Injection.

    pattern-sources:
      - pattern: ProcessBuilder.new $CONSTR(...)
      - pattern: new ProcessBuilder($PARAM)
      - pattern: new ProcessBuilder()
```
````

> More information on creating OpenGrep rules: https://semgrep.dev/learn
> For most Nika use cases, a simple source/sink pattern is sufficient — complex rules are usually not required.

---

### Define a Plugin

A plugin defines the vulnerability metadata, execution stages, and optional AI-assisted false positive analysis.

Example plugin for Command Injection:

````md
```python
class CommandInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "command_injection"
    title = "Command Injection"
    description = (
        "Command Injection vulnerability allows attackers to execute arbitrary "
        "commands on the host operating system by injecting malicious input."
    )

    supported_languages = ["java"]

    required_engine_roles = [
        "sink_finder",
        "source_finder",
        "dataflow_analyzer"
    ]

    source_types = ["remote_input"]

    prompt_kind = "trace"

    stages = [
        match_rule_sinks,
        discover_sources,
        run_dataflow,
        review_traces_with_llm,
        finalize_findings,
    ]

    optional_stages = [
        review_traces_with_llm
    ]

    review_mode = "optional"

    system_prompt = (
        "Review this trace for command injection risk..."
    )

    human_prompt = (
        "Analyze this command injection trace..."
    )

    fallback_explanation = (
        "Trace reached a command execution sink..."
    )

    fallback_remediation = (
        "Avoid shell invocation..."
    )

    fallback_code_fix = (
        "Replace command-string construction..."
    )
```
````

#### Plugin Parameters

| Parameter               | Description                                             |
| ----------------------- | ------------------------------------------------------- |
| `vulnerability_id`      | Unique identifier for the vulnerability type            |
| `title`                 | Human-readable vulnerability name                       |
| `description`           | Short explanation of the vulnerability                  |
| `supported_languages`   | Languages supported for this plugin                     |
| `required_engine_roles` | Analysis engines required for execution                 |
| `source_types`          | Types of sources considered during analysis             |
| `prompt_kind`           | Defines how traces are passed for review                |
| `stages`                | Ordered execution pipeline for the vulnerability        |
| `optional_stages`       | Stages that may be skipped                              |
| `review_mode`           | Controls whether review is mandatory or optional        |
| `system_prompt`         | Internal instructions used during false positive review |
| `human_prompt`          | Context provided to assist review decisions             |
| `fallback_explanation`  | Explanation shown when review is unavailable            |
| `fallback_remediation`  | Suggested remediation guidance                          |
| `fallback_code_fix`     | Example direction for fixing the issue                  |

After defining a source, sink, and plugin, Nika can identify the vulnerability and optionally perform false positive analysis on discovered traces.


## Use Cases

This section covers common extension scenarios in Nika.

Nika vulnerabilities are implemented using:

* **Sources** → Define where untrusted data enters.
* **OpenGrep Rules** → Define sinks and matching patterns.
* **Plugins** → Define execution stages and vulnerability metadata.

Use the following guide depending on what you want to extend.

| Use Case                                    | Changes Required                                         |
| ------------------------------------------- | -------------------------------------------------------- |
| Add a new source                            | Update `crtConfig.yml` or `native-crtConfig.yml`         |
| Add a new sink to an existing vulnerability | Add OpenGrep rules under `rules/<vulnerability_id>/java` |
| Add a new vulnerability type                | Add rules, create a plugin, and register it              |

---

### Add a New Source

Use this when Nika should recognize additional application entry points.

Modify:

```text
crtConfig.yml
```

or

```text
native-crtConfig.yml
```

Example:

````md
```yaml
sources:
  annotations:
    - "@RequestMapping"
    - "@GetMapping"
    - "@Path"
```
````

---

### Add a New Sink to an Existing Vulnerability

Use this when:

* the vulnerability already exists,
* but detection coverage needs expansion.

Modify:

```text
rules/<vulnerability_id>/java
```

Example:

```text
rules/command_injection/java
```

Add a new OpenGrep rule.

---

### Add a New Vulnerability Type

Use this when the vulnerability category does not exist in Nika.

Required steps:

1. Add OpenGrep rules

```text
rules/<vulnerability_id>/java
```

2. Create a plugin

```text
vulnerabilities/<vulnerability>.py
```

3. Register the vulnerability

```text
runtime/registry.py
```

---

### Select the Detection Model

| Model       | Use When                                  |
| ----------- | ----------------------------------------- |
| Sink-only   | Sink match alone is sufficient            |
| Trace-based | Source → Sink reachability must be proven |

Sink-only:

```python
required_engine_roles = ["sink_finder"]
source_types = []
review_mode = "never"
```

Trace-based:

```python
required_engine_roles = [
    "sink_finder",
    "source_finder",
    "dataflow_analyzer"
]

source_types = ["remote_input"]
review_mode = "optional"
```

As a general rule:

* Choose **sink-only** for direct dangerous API usage.
* Choose **trace-based** when reachability should be proven before reporting.
