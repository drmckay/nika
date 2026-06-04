

## Minimum Requirements

| Component | Supported Versions |
|------------|-------------------|
| Operating System | macOS, Linux |
| Python | 3.10+ |
| RAM | 4 GB minimum (8 GB recommended) |
| Disk Space | 4 GB available |
| Architecture | x86_64, ARM64 |
| Library | coreutils |


## Configuration

Nika loads its settings from YAML configuration.

- Default sample config: `config/crtConfig.yml`
- local config target when running via provided bash script: `config/native-crtConfig.yml`

The configuration controls scan behavior, enabled vulnerabilities, engine tool paths, and the optional exploitability review step.

If you want Nika to run the AI-powered exploitability check, enable LLM review and provide the model settings it needs.

### Configuration Fields

1. `LLMConfig`: Top-level settings for the optional LLM-backed exploitability review.
2. `LLMConfig.API_KEY`: API key used to authenticate with the configured LLM provider or gateway.
3. `LLMConfig.LLM_URL`: Base URL for the LLM endpoint.
4. `LLMConfig.MODEL`: Model identifier used when the review agent is enabled.
5. `LLMConfig.MAX_TOOL_CALLS`: Maximum number of tool invocations the review agent can make in a single run.
6. `LLMConfig.MAX_ITERATIONS`: Maximum number of review iterations the agent can perform before stopping.
7. `LLMConfig.RECURSION_LIMIT`: Safety limit for nested agent execution depth.
8. `LLMConfig.PROMPT_COST_PER_MILLION`: Cost metadata for prompt tokens, used when tracking review usage.
9. `LLMConfig.COMPLETION_COST_PER_MILLION`: Cost metadata for completion tokens, used alongside prompt pricing.
10. `llm_review_enabled`: Enables or disables the LLM-assisted exploitability review stage.
11. `aggressiveScan`: Turns on a more aggressive reachability analysis mode that can uncover deeper paths at the cost of more false positives.
12. `sources.annotations`: List of framework annotations that should be treated as taint-entry points.
13. `max_threads`: Number of worker threads available for scan execution.
14. `vulnerabilityConfig`: List of vulnerability categories to include in the current scan.
15. `vulnerabilityArgs`: Per-vulnerability overrides or detector arguments, such as keyword lists for `sensitive_logging`.
16. `tools`: Tool-specific configuration used by analysis engines.
17. `tools.astrail.astrailpath`: Path to the Astrail binary.
18. `tools.astrail.javasrc2cpg`: Path to the `javasrc2cpg` binary used to build the code property graph.
19. `tools.astrail.port`: Port used by the Astrail service.
20. `tools.opengrep.path`: Path to the OpenGrep binary.

### Local Scan

Use this when you want a local Python environment, local tool installs, and faster scan results.

1. Clone nika repository

	```bash
	git clone https://github.com/PhonePe/nika.git
	```

2. Prepare the native environment:

	```bash
	cd nika
	./native-build.sh
	```

	`native-build.sh` sets up the virtual environment, installs dependencies, prepares native tools, and writes the native config used by the launcher.

3. Run the scan:

	```bash
	./native-run.sh --path /absolute/path/to/code --output ./report.html
	```

### Scan via Docker

Use this when you want an isolated runtime with the scan environment packaged into a Docker image.

1. Clone nika repository

	```bash
	git clone https://github.com/PhonePe/nika.git
	```

2. Build the image:

	```bash
	cd nika
	./build.sh
	```

	`build.sh` creates the `nika:latest` image by default.

3. Run the scan:

	```bash
	./run.sh --path /absolute/path/to/code --config /absolute/path/to/crtConfig.yml --output ./report.html
	```