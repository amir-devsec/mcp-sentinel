"""
MCP-Sentinel: Static Security Linter & Auditor for Model Context Protocol (MCP) Servers.
"""

import ast
import json
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None


class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        # MCP-SEC-01: Опасное выполнение shell-команд
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if func_name in ("system", "popen"):
                self.findings.append(
                    Finding(
                        rule_id="MCP-SEC-01",
                        severity=Severity.CRITICAL,
                        title="Arbitrary Shell Execution",
                        description=f"Прямой вызов os.{func_name}() в туле агента. Высокий риск RCE.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        snippet=ast.unparse(node),
                    )
                )

            if func_name in ("run", "Popen", "call", "check_output"):
                for keyword in node.keywords:
                    if keyword.arg == "shell" and getattr(keyword.value, "value", None) is True:
                        self.findings.append(
                            Finding(
                                rule_id="MCP-SEC-01",
                                severity=Severity.CRITICAL,
                                title="Subprocess with shell=True",
                                description="Использование shell=True позволяет агенту выполнять инъекции шелл-команд.",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                snippet=ast.unparse(node),
                            )
                        )

            # MCP-SEC-03: Потенциальный SSRF
            if func_name in ("get", "post", "put", "delete", "request"):
                for arg in node.args:
                    arg_str = ast.unparse(arg).lower()
                    if "localhost" in arg_str or "127.0.0.1" in arg_str or "0.0.0.0" in arg_str:
                        self.findings.append(
                            Finding(
                                rule_id="MCP-SEC-03",
                                severity=Severity.HIGH,
                                title="Loopback Network Access (SSRF Risk)",
                                description="Сетевой запрос обращается к loopback/внутренней сети хоста.",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                snippet=ast.unparse(node),
                            )
                        )

        # Вызов встроенных eval / exec
        elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.findings.append(
                Finding(
                    rule_id="MCP-SEC-01",
                    severity=Severity.CRITICAL,
                    title="Dynamic Code Evaluation (eval/exec)",
                    description=f"Использование встроенной функции {node.func.id}() недопустимо в логике AI-тулов.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    snippet=ast.unparse(node),
                )
            )

        self.generic_visit(node)


class MCPSentinel:
    SECRET_REGEXES = {
        "Anthropic API Key": r"sk-ant-[a-zA-Z0-9_\-]{30,}",
        "OpenAI API Key": r"sk-[a-zA-Z0-9]{20,}",
        "Generic Secret Token": r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
        "AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"][a-zA-Z0-9/+=]{40}['\"]",
    }

    INJECTION_INDICATORS = [
        r"(?i)system\s+prompt",
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)always\s+(call|execute)\s+this",
        r"(?i)bypass\s+safety",
        r"(?i)do\s+not\s+tell\s+the\s+user",
    ]

    def __init__(self):
        self.findings: List[Finding] = []

    def scan_python_code(self, file_path: Path):
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return

        # 1. Поиск секретов
        for secret_name, regex in self.SECRET_REGEXES.items():
            for match in re.finditer(regex, content):
                line_no = content.count("\n", 0, match.start()) + 1
                self.findings.append(
                    Finding(
                        rule_id="MCP-SEC-04",
                        severity=Severity.CRITICAL,
                        title=f"Hardcoded {secret_name}",
                        description="В исходном коде обнаружен незашифрованный секрет или токен доступа.",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=match.group(0)[:15] + "..." + match.group(0)[-4:],
                    )
                )

        # 2. AST анализ
        try:
            tree = ast.parse(content, filename=str(file_path))
            visitor = ASTSecurityVisitor(str(file_path))
            visitor.visit(tree)
            self.findings.extend(visitor.findings)
        except SyntaxError:
            pass

    def scan_config_or_manifest(self, file_path: Path):
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return

        # Проверка секретов в json-конфигах
        for secret_name, regex in self.SECRET_REGEXES.items():
            for match in re.finditer(regex, content):
                line_no = content.count("\n", 0, match.start()) + 1
                self.findings.append(
                    Finding(
                        rule_id="MCP-SEC-04",
                        severity=Severity.CRITICAL,
                        title=f"Plaintext {secret_name} in Config",
                        description="Конфиг MCP содержит открытые секреты вместо ссылок на переменные окружения.",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=match.group(0)[:12] + "****",
                    )
                )

        # Парсинг JSON схем и тулов на предмет Indirect Prompt Injection в description
        try:
            data = json.loads(content)
            self._audit_json_object(data, str(file_path))
        except json.JSONDecodeError:
            pass

    def _audit_json_object(self, obj, file_path: str):
        if isinstance(obj, dict):
            # Проверка описания инструментов (tool definitions)
            if "description" in obj and isinstance(obj["description"], str):
                desc = obj["description"]
                for pattern in self.INJECTION_INDICATORS:
                    if re.search(pattern, desc):
                        self.findings.append(
                            Finding(
                                rule_id="MCP-SEC-05",
                                severity=Severity.HIGH,
                                title="Tool Shadowing / Indirect Injection Vector",
                                description="Описание тула содержит директивы перезаписи поведения LLM.",
                                file_path=file_path,
                                snippet=desc[:80] + "...",
                            )
                        )
            for v in obj.values():
                self._audit_json_object(v, file_path)
        elif isinstance(obj, list):
            for item in obj:
                self._audit_json_object(item, file_path)

    def scan_directory(self, target_dir: str):
        path = Path(target_dir)
        for p in path.rglob("*"):
            if any(part.startswith(".") or part in ("venv", "node_modules", "__pycache__") for part in p.parts):
                continue
            if p.suffix == ".py":
                self.scan_python_code(p)
            elif p.suffix in (".json", ".yaml", ".yml"):
                self.scan_config_or_manifest(p)

    def print_report(self):
        console.print(
            Panel.fit(
                "[bold cyan]🛡️ MCP-Sentinel v1.0.0[/bold cyan]\n"
                "[dim]Static Security Linter for AI Agents & Model Context Protocol Servers[/dim]",
                border_style="cyan",
            )
        )

        if not self.findings:
            console.print("\n[bold green]✔ Уязвимостей не найдено! MCP-сервер чист.[/bold green]\n")
            return 0

        table = Table(title="Security Findings", expand=True)
        table.add_column("Severity", justify="center", style="bold", width=12)
        table.add_column("Rule", style="dim", width=14)
        table.add_column("Issue", style="bold white", width=30)
        table.add_column("Location", style="yellow")
        table.add_column("Snippet / Context", style="dim cyan")

        severity_colors = {
            Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
            Severity.HIGH: "[bold orange3]HIGH[/bold orange3]",
            Severity.MEDIUM: "[bold yellow]MEDIUM[/bold yellow]",
            Severity.LOW: "[bold blue]LOW[/bold blue]",
            Severity.INFO: "[dim]INFO[/dim]",
        }

        for f in self.findings:
            loc = f.file_path
            if f.line_number:
                loc += f":{f.line_number}"
            table.add_row(
                severity_colors.get(f.severity, str(f.severity)),
                f.rule_id,
                f.title,
                loc,
                f.snippet or "-",
            )

        console.print(table)

        crit_count = sum(1 for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
        console.print(f"\n[bold red]Всего найдено угроз:[/bold red] {len(self.findings)} (Критичных: {crit_count})")
        return 1 if crit_count > 0 else 0


if __name__ == "__main__":
    scan_target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = MCPSentinel()
    scanner.scan_directory(scan_target)
    sys.exit(scanner.print_report())