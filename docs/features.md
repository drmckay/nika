## Core Features

Nika is built to find security issues that depend on how data moves through a real codebase, not just within a single function. The most important capability is its **cross-file taint analysis**, supported by branch-aware scanning and an aggressive reachability mode for harder code paths.

### Cross-File Taint Analysis

Cross-file taint analysis is the core feature of Nika. It tracks attacker-controlled input from the point where it enters the application, follows how that input is propagated through methods and classes, and checks whether the flow reaches a security-sensitive sink.

This matters because many exploitable paths do not stay inside one file. In a typical Java service, request data may enter through a controller, pass through a DTO mapper, move into a service layer, and finally reach a sink such as a database query, file operation, template renderer, or outbound network call. A single-file rule can miss that path. Nika is designed to keep following it.

Nika's cross-file taint analysis helps you:

* trace input across controllers, services, helpers, and utility classes,
* identify inter-procedural source-to-sink paths instead of isolated risky calls,
* reduce noise by requiring a realistic propagation path before reporting a finding,
* uncover vulnerabilities that only become visible when multiple files participate in the flow.

This is especially useful for vulnerability classes such as **SSRF**, **SQL injection**, **Path Traversal**, **Code Injection**, **Template Injection**, and **XXE**, where the dangerous behavior is often assembled gradually across multiple layers of the application.

For example, consider this command-injection flow spread across three files:

`DomainController.java` receives attacker-controlled input.

```java
@PostMapping("/test-domain")
public ResponseEntity<String> testDomain(@RequestBody DomainTestRequest request) {
  String output = domainTestService.testDomain(request.getDomainName());
  return ResponseEntity.ok(output);
}
```

`DomainTestService.java` forwards the value through the service layer.

```java
public String testDomain(String domainName) {
  String command = commandBuilder.buildPingCommand(domainName);
  return commandExecutor.run(command);
}
```

`CommandBuilder.java` constructs the shell command that eventually reaches the sink.

```java
@Component
public class CommandBuilder {
  public String buildPingCommand(String domainName) {
    return "sh -c \"ping -c 1 " + domainName + "\"";
  }
}
```

`CommandExecutor.java` contains the security-sensitive sink.

```java
@Component
public class CommandExecutor {
  public String run(String command) {
    try {
      Process process = Runtime.getRuntime().exec(command);
      return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException exception) {
      throw new IllegalStateException("Unable to execute command", exception);
    }
  }
}
```

In this case, Nika can trace the data flow from the request body in `DomainController.java`, through `DomainTestService.java` and `CommandBuilder.java`, and into the command-execution sink in `CommandExecutor.java`. That is the kind of path a single-file matcher often misses, but a cross-file taint engine is designed to recover.

### Branch-Aware Scan

Use branch-aware scanning when you want baseline-aware behavior. Nika compares the source and target branches to identify the baseline commit, which helps you focus on changes introduced by the branch under review instead of treating the entire repository as equally new.

```bash
python3 main.py \
	--path "/absolute/path/to/git/repo" \
	--lang java \
	--source_branch feature-branch \
	--target_branch main \
	--output report.html
```

When both branch arguments are provided, the runtime computes a merge base and uses that baseline during analysis. This is useful in CI pipelines, pull request reviews, and release validation workflows where you want scan results to stay aligned with the branch diff.

### Aggressive Scan

Use `aggressiveScan` when the default reachability pass is too shallow for the codebase you are scanning.

`aggressiveScan` switches Astrail to method-level reachability checks. That can recover flows that the normal reachability pass misses.

This mode is most useful when the application has:

* complex virtual dispatch,
* layered interfaces and abstractions,
* framework callbacks.

In those cases, Nika may still identify sources and sinks, but the default pass may fail to connect them into a usable trace. Aggressive mode increases the chances of recovering the missing flow so the final report includes a concrete source-to-sink path.

For example, consider a service that routes user-controlled actions through a map-based dispatch table:

```java
@PostMapping("/jobs/run")
public ResponseEntity<Void> runJob(@RequestBody JobRequest request) {
  jobService.run(request.getAction(), request.getPayload());
  return ResponseEntity.accepted().build();
}
```

```java
@Service
public class JobService {
  private final Map<String, Consumer<String>> handlers;

  public JobService(CommandHandler commandHandler, AuditHandler auditHandler) {
    this.handlers = Map.of(
      "cmd", commandHandler::handle,
      "audit", auditHandler::handle
    );
  }

  public void run(String action, String payload) {
    Consumer<String> handler = handlers.getOrDefault(action, audit -> {});
    handler.accept(payload);
  }
}
```

```java
@Component
public class CommandHandler {
  public void handle(String payload) {
    Runtime.getRuntime().exec(payload);
  }
}
```

Here the source starts in the controller, but the call to the sink is hidden behind a `Map<String, Consumer<String>>` lookup and an indirect `accept` call. That kind of dispatch pattern can be difficult for a shallow reachability pass to resolve. `aggressiveScan` helps recover the path from `request.getPayload()` to `Runtime.getRuntime().exec(payload)` so the final trace still shows a concrete command-injection flow.

### AI-Powered Exploitability Check

Finding a source-to-sink path is useful, but it does not always tell you whether the issue can really be used in practice.

Nika includes an optional AI-powered exploitability check that reviews each finding in context and helps determine whether the reported path is actually exploitable. Instead of stopping at the sink, the agent looks at the surrounding code for the details that often decide whether a report is actionable, such as validation logic, allowlists, guard clauses, wrapper methods, feature flags, and other controls that may block or constrain the flow.

Because the agent has tool access to search the codebase, it is not limited to the file where the finding was raised. It can inspect related classes, helper methods, and nearby implementation details to understand how the path behaves across the application. That makes it easier to separate a theoretical path from one that can actually be exercised.

When this check is enabled, teams can spend less time chasing dead ends and more time focusing on findings that are genuinely worth fixing first. If it is not enabled, someone needs to manually review the findings to decide whether the reported issue is truly exploitable.

### Why These Features Work Together

These capabilities are complementary:

* **Cross-file taint analysis** finds realistic exploit paths across the application.
* **Branch-aware scanning** keeps results focused on the code changes that matter for the current review.
* **Aggressive scan** improves reachability in codebases where the default path resolution misses valid flows.
* **AI-powered exploitability check** helps teams understand whether a reported path is actually actionable.

Together, they make Nika better suited for scanning modern service-oriented Java applications, where vulnerable data paths are rarely local, direct, or easy to detect with pattern matching alone.
