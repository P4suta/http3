#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""AST audit for authored Python native-process and console capabilities."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import sys
from pathlib import Path


ROOTS = (
    Path("src"), Path("test"), Path("scripts"),
    Path("packages/http3/src"), Path("packages/http3/test"),
    Path("packages/quic_core/src"), Path("packages/quic_core/test"),
)
MAX_FILES = 2048
MAX_BYTES = 2_097_152
LAUNCH_MEMBERS = {
    "Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"
}
ASYNC_MEMBERS = {"create_subprocess_exec", "create_subprocess_shell"}
OS_MEMBERS = {"popen", "system"}
OWNED_MEMBERS = {"owned_popen", "owned_run", "owned_check_output"}
MAX_OWNED_CALL_OUTPUT_BYTES = 16_777_216
FORBIDDEN_NAMES = {"CREATE_NEW_CONSOLE", "DETACHED_PROCESS", "AllocConsole"}


# This deliberately duplicates the accepted launch boundary as syntax rather than trusting comments, strings, unordered fragments, or a filename.
# The Erlang runner separately pins the complete supervisor source digest.
OWNED_POPEN_FORM = ast.dump(ast.parse('''\
def owned_popen(
    argv: Sequence[str], *, supervisor_root: bool = False, **options: object
) -> subprocess.Popen[bytes]:
    """The repository's single native launch primitive.

    Windows children inherit the verified ConPTY owned by the supervisor.
    Other authored Python callers inherit the already-owned Job/group.
    """
    if options.get("shell") is True:
        raise SupervisorFailure("protocol_failure")
    options["close_fds"] = True
    if os.name == "nt":
        requested = int(options.pop("creationflags", 0))
        if requested != 0:
            raise SupervisorFailure("protocol_failure")
        if supervisor_root or not windows_console_attached():
            raise SupervisorFailure("console_isolation_unconfirmed")
        options["creationflags"] = requested
        options.pop("start_new_session", None)
    else:
        options.pop("creationflags", None)
        options["start_new_session"] = supervisor_root
    return subprocess.Popen(list(argv), **options)
''').body[0], include_attributes=False)

CONSOLE_FIXTURE_FORMS = {
    node.name: ast.dump(node, include_attributes=False)
    for node in ast.parse('''\
def leaf() -> int:
    if not windows_console_attached():
        return 1
    sys.stdout.buffer.write(b"console_attached=true\\n")
    sys.stdout.buffer.flush()
    time.sleep(0.25)
    return 0

def root() -> int:
    if not windows_console_attached():
        return 1
    result = owned_run(
        [sys.executable, "-E", "-s", "-B", str(Path(__file__)), "--leaf"],
        timeout=5.0,
        max_output_bytes=64,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0 or result.stdout != b"console_attached=true\\n":
        return 1
    sys.stdout.buffer.write(
        b"console_inheritance_fixture passed=true generations=2\\n"
    )
    sys.stdout.buffer.flush()
    return 0
''').body
}


class Audit(ast.NodeVisitor):
    def __init__(self, path: str, assigned_names: set[str]) -> None:
        self.path = path.replace("\\", "/")
        self.modules: dict[str, str] = {}
        self.members: dict[str, tuple[str, str]] = {}
        self.assigned_names = assigned_names
        self.functions: list[str] = []
        self.owned_popen_forms: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self.owned_run_forms: list[ast.FunctionDef] = []
        self.owned_check_output_forms: list[ast.FunctionDef] = []
        self.owned_run_helpers: dict[str, list[ast.FunctionDef]] = {}
        self.pseudoconsole_forms: list[ast.FunctionDef] = []
        self.pre_resume_close_forms: list[ast.FunctionDef] = []
        self.posix_supervise_forms: list[ast.FunctionDef] = []
        self.windows_supervise_forms: list[ast.FunctionDef] = []
        self.resume_forms: list[ast.FunctionDef] = []
        self.console_drain_close_forms: list[ast.FunctionDef] = []
        self.process_handle_close_forms: list[ast.FunctionDef] = []
        self.output_relay_forms: list[ast.FunctionDef] = []
        self.console_attachment_forms: list[ast.FunctionDef] = []
        self.abnormal_exit_forms: list[ast.FunctionDef] = []
        self.console_fixture_forms: dict[str, list[ast.FunctionDef]] = {}
        self.launches: list[dict[str, object]] = []
        self.unsafe: list[dict[str, object]] = []

    def row(self, line: int, rule: str) -> dict[str, object]:
        return {"path": self.path, "line": max(1, line), "rule": rule}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in {"subprocess", "asyncio", "os", "process_supervisor"}:
                self.modules[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module is not None:
            for alias in node.names:
                if (node.module in {"subprocess", "asyncio", "os", "process_supervisor"}
                        or alias.name in OWNED_MEMBERS):
                    self.members[alias.asname or alias.name] = (node.module, alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name == "owned_popen":
            self.owned_popen_forms.append(node)
        if node.name == "owned_run":
            self.owned_run_forms.append(node)
        if node.name == "owned_check_output":
            self.owned_check_output_forms.append(node)
        if node.name in {
            "owned_operation_deadline", "owned_remaining", "owned_close_stream",
            "owned_close_streams", "owned_record_failure",
            "owned_observed_failure", "owned_capture_pipe",
            "owned_input_closed_early", "owned_write_input", "owned_join_workers",
        }:
            self.owned_run_helpers.setdefault(node.name, []).append(node)
        if node.name == "create_windows_pseudoconsole_child":
            self.pseudoconsole_forms.append(node)
        if node.name == "close_console_before_resume":
            self.pre_resume_close_forms.append(node)
        if node.name == "supervise_posix":
            self.posix_supervise_forms.append(node)
        if node.name == "supervise_windows":
            self.windows_supervise_forms.append(node)
        if node.name == "resume":
            self.resume_forms.append(node)
        if node.name == "close_console_while_draining":
            self.console_drain_close_forms.append(node)
        if node.name == "close_process_handles":
            self.process_handle_close_forms.append(node)
        if node.name == "output_relay":
            self.output_relay_forms.append(node)
        if node.name == "windows_console_attached":
            self.console_attachment_forms.append(node)
        if node.name == "windows_abnormal_exit_category":
            self.abnormal_exit_forms.append(node)
        if (self.path == "scripts/process_console_inheritance_fixture.py"
                and node.name in CONSOLE_FIXTURE_FORMS):
            self.console_fixture_forms.setdefault(node.name, []).append(node)
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        names = {item.id for item in ast.walk(node.type)
                 if isinstance(item, ast.Name)} if node.type is not None else set()
        if (self.path == "scripts/process_supervisor.py"
                and self.functions == ["main"] and "OSError" in names):
            self.unsafe.append(self.row(
                node.lineno, "broad_post_spawn_oserror_attestation"
            ))
        self.generic_visit(node)

    def target(self, node: ast.expr) -> tuple[str, str] | None:
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = self.modules.get(node.value.id, node.value.id)
            return module, node.attr
        if isinstance(node, ast.Name):
            return self.members.get(node.id)
        return None

    def keyword(self, node: ast.Call, name: str) -> ast.expr | None:
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    @staticmethod
    def true_literal(node: ast.expr | None) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    @staticmethod
    def contains_names(node: ast.AST | None, required: set[str]) -> bool:
        if node is None:
            return False
        found = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
        return required.issubset(found)

    def supervisor_call_safe(self, node: ast.Call) -> bool:
        return (self.path == "scripts/process_supervisor.py"
                and self.functions == ["owned_popen"]
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Call)
                and isinstance(node.args[0].func, ast.Name)
                and node.args[0].func.id == "list"
                and len(node.args[0].args) == 1
                and isinstance(node.args[0].args[0], ast.Name)
                and node.args[0].args[0].id == "argv"
                and len(node.keywords) == 1
                and node.keywords[0].arg is None
                and isinstance(node.keywords[0].value, ast.Name)
                and node.keywords[0].value.id == "options")

    def bounded_owned_call_safe(self, node: ast.Call, member: str) -> bool:
        if member == "owned_popen":
            return True
        caps = [keyword.value for keyword in node.keywords
                if keyword.arg == "max_output_bytes"]
        return (
            len(caps) == 1
            and isinstance(caps[0], ast.Constant)
            and isinstance(caps[0].value, int)
            and not isinstance(caps[0].value, bool)
            and 0 <= caps[0].value <= MAX_OWNED_CALL_OUTPUT_BYTES
            and all(keyword.arg is not None for keyword in node.keywords)
        )

    def visit_Call(self, node: ast.Call) -> None:
        target = self.target(node.func)
        is_launch = False
        if target is not None:
            module, member = target
            is_launch = ((module == "subprocess" and member in LAUNCH_MEMBERS) or
                         (module == "asyncio" and member in ASYNC_MEMBERS) or
                         (module == "os" and member in OS_MEMBERS))
        if is_launch:
            safe = target == ("subprocess", "Popen") and self.supervisor_call_safe(node)
            self.launches.append(self.row(node.lineno,
                "pinned_supervisor_launcher" if safe else "unowned_python_native_spawn"))
            if not safe:
                self.unsafe.append(self.row(node.lineno, "unowned_python_native_spawn"))
            if self.true_literal(self.keyword(node, "shell")):
                self.unsafe.append(self.row(node.lineno, "python_shell_spawn"))
        if target is not None and target[1] in OWNED_MEMBERS:
            direct_name = node.func.id if isinstance(node.func, ast.Name) else None
            safe_boundary = (target[0] == "process_supervisor"
                             and (direct_name is None or direct_name not in self.assigned_names)
                             and self.bounded_owned_call_safe(node, target[1]))
            self.launches.append(self.row(node.lineno,
                "owned_python_process_boundary" if safe_boundary
                else "untrusted_python_process_boundary"))
            if not safe_boundary:
                self.unsafe.append(self.row(node.lineno,
                    "untrusted_python_process_boundary"))
        name = node.func.attr if isinstance(node.func, ast.Attribute) else (
            node.func.id if isinstance(node.func, ast.Name) else "")
        if name == "AllocConsole":
            self.unsafe.append(self.row(node.lineno, "alloc_console"))
        if name == "CreateProcessW":
            safe = (self.path == "scripts/process_supervisor.py"
                    and self.functions == ["create_windows_pseudoconsole_child"]
                    and pseudoconsole_create_call_safe(node))
            self.launches.append(self.row(node.lineno,
                "pseudoconsole_root_launcher" if safe
                else "unowned_windows_create_process"))
            if not safe:
                self.unsafe.append(self.row(node.lineno,
                    "unowned_windows_create_process"))
        self.generic_visit(node)

    def validate_boundary(self) -> None:
        if self.path == "scripts/process_supervisor.py":
            valid = (len(self.owned_popen_forms) == 1 and
                     ast.dump(self.owned_popen_forms[0], include_attributes=False)
                     == OWNED_POPEN_FORM)
            if not valid:
                line = (self.owned_popen_forms[0].lineno
                        if self.owned_popen_forms else 1)
                self.unsafe.append(self.row(line,
                                           "invalid_owned_popen_boundary"))
            valid_owned_run = (
                len(self.owned_run_forms) == 1
                and owned_run_boundary_safe(
                    self.owned_run_forms[0], self.owned_run_helpers
                )
            )
            if not valid_owned_run:
                line = (self.owned_run_forms[0].lineno
                        if self.owned_run_forms else 1)
                self.unsafe.append(self.row(
                    line, "invalid_bounded_owned_run_boundary"
                ))
            valid_check_output = (
                len(self.owned_check_output_forms) == 1
                and owned_check_output_boundary_safe(
                    self.owned_check_output_forms[0]
                )
            )
            if not valid_check_output:
                line = (self.owned_check_output_forms[0].lineno
                        if self.owned_check_output_forms else 1)
                self.unsafe.append(self.row(
                    line, "invalid_bounded_owned_check_output_boundary"
                ))
            valid_conpty = (
                len(self.pseudoconsole_forms) == 1
                and pseudoconsole_boundary_safe(self.pseudoconsole_forms[0])
            )
            if not valid_conpty:
                line = (self.pseudoconsole_forms[0].lineno
                        if self.pseudoconsole_forms else 1)
                self.unsafe.append(self.row(
                    line, "invalid_pseudoconsole_boundary"
                ))
            valid_suspended_close = (
                len(self.pre_resume_close_forms) == 1
                and pre_resume_close_boundary_safe(
                    self.pre_resume_close_forms[0]
                )
            )
            if not valid_suspended_close:
                line = (self.pre_resume_close_forms[0].lineno
                        if self.pre_resume_close_forms else 1)
                self.unsafe.append(self.row(
                    line, "invalid_suspended_console_cleanup"
                ))
            valid_posix = (len(self.posix_supervise_forms) == 1
                           and posix_supervisor_boundary_safe(
                               self.posix_supervise_forms[0]))
            if not valid_posix:
                line = (self.posix_supervise_forms[0].lineno
                        if self.posix_supervise_forms else 1)
                self.unsafe.append(self.row(
                    line, "invalid_posix_process_group_boundary"
                ))
            valid_windows = (len(self.windows_supervise_forms) == 1
                             and windows_supervisor_boundary_safe(
                                 self.windows_supervise_forms[0]))
            if not valid_windows:
                line = (self.windows_supervise_forms[0].lineno
                        if self.windows_supervise_forms else 1)
                self.unsafe.append(self.row(
                    line, "invalid_windows_job_cleanup_boundary"
                ))
            lifecycle_forms = [
                (self.resume_forms, resume_boundary_safe,
                 "invalid_suspended_resume_boundary"),
                (self.console_drain_close_forms,
                 console_drain_close_boundary_safe,
                 "invalid_conpty_drain_close_boundary"),
                (self.process_handle_close_forms,
                 process_handle_close_boundary_safe,
                 "invalid_process_handle_cleanup"),
                (self.output_relay_forms, output_relay_boundary_safe,
                 "invalid_bounded_output_relay"),
                (self.console_attachment_forms,
                 console_attachment_boundary_safe,
                 "invalid_console_job_attachment_proof"),
            ]
            for forms, validator, rule in lifecycle_forms:
                if len(forms) != 1 or not validator(forms[0]):
                    self.unsafe.append(self.row(
                        forms[0].lineno if forms else 1, rule
                    ))
            if (len(self.abnormal_exit_forms) != 1
                    or ast.dump(
                        self.abnormal_exit_forms[0], include_attributes=False
                    ) != WINDOWS_ABNORMAL_EXIT_FORM):
                self.unsafe.append(self.row(
                    self.abnormal_exit_forms[0].lineno
                    if self.abnormal_exit_forms else 1,
                    "invalid_finite_windows_abnormal_exit_classification",
                ))
        if self.path == "scripts/process_console_inheritance_fixture.py":
            valid_fixture = all(
                len(self.console_fixture_forms.get(name, [])) == 1
                and ast.dump(self.console_fixture_forms[name][0],
                             include_attributes=False) == expected
                for name, expected in CONSOLE_FIXTURE_FORMS.items()
            )
            if not valid_fixture:
                self.unsafe.append(self.row(1,
                    "invalid_console_inheritance_fixture"))

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in {"CREATE_NEW_CONSOLE", "DETACHED_PROCESS"}:
            safe_guard = (self.path == "scripts/process_supervisor.py"
                          and self.functions == ["owned_popen"])
            safe_definition = (self.path == "scripts/process_supervisor.py"
                               and not self.functions
                               and isinstance(node.ctx, ast.Store))
            if not safe_guard and not safe_definition:
                self.unsafe.append(self.row(node.lineno, node.id.lower()))


def pseudoconsole_create_call_safe(node: ast.Call) -> bool:
    if len(node.args) != 10 or node.keywords:
        return False
    (application, command, process_security, thread_security, inherit, flags,
     environment, directory, startup, process) = node.args
    expected_flags = ast.parse(
        "EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | "
        "CREATE_SUSPENDED", mode="eval").body
    expected_startup = ast.parse(
        "ctypes.byref(startup.StartupInfo)", mode="eval").body
    expected_process = ast.parse("ctypes.byref(process)", mode="eval").body
    return (
        isinstance(application, ast.Subscript)
        and isinstance(application.value, ast.Name)
        and application.value.id == "argv"
        and isinstance(application.slice, ast.Constant)
        and application.slice.value == 0
        and isinstance(command, ast.Name) and command.id == "command_line"
        and all(isinstance(value, ast.Constant) and value.value is None
                for value in [process_security, thread_security,
                              environment, directory])
        and isinstance(inherit, ast.Constant) and inherit.value is False
        and ast.dump(flags, include_attributes=False)
            == ast.dump(expected_flags, include_attributes=False)
        and ast.dump(startup, include_attributes=False)
            == ast.dump(expected_startup, include_attributes=False)
        and ast.dump(process, include_attributes=False)
            == ast.dump(expected_process, include_attributes=False)
    )


def pseudoconsole_attribute_call_safe(node: ast.Call) -> bool:
    expected = ast.parse('''KERNEL32.UpdateProcThreadAttribute(
        attribute_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        ctypes.c_void_p(int(pseudoconsole.value)),
        ctypes.sizeof(ctypes.c_void_p),
        None, None
    )''', mode="eval").body
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected, include_attributes=False
    )


def qualified_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def statement_dump(source: str) -> str:
    return ast.dump(ast.parse(source).body[0], include_attributes=False)


def structural_function_dump(node: ast.FunctionDef) -> str:
    """Compare executable structure while retaining only docstring presence.

    A method's source indentation is part of the raw docstring value even
    though it has no effect on execution.  Normalising that value keeps this
    boundary check exact for every executable AST field without coupling it to
    the surrounding class indentation.
    """
    clone = copy.deepcopy(node)
    if (clone.body and isinstance(clone.body[0], ast.Expr)
            and isinstance(clone.body[0].value, ast.Constant)
            and isinstance(clone.body[0].value.value, str)):
        clone.body[0].value.value = "verified_docstring_present"
    return ast.dump(clone, include_attributes=False)


def direct_statement_index(statements: list[ast.stmt], expected: str) -> int:
    matches = [index for index, statement in enumerate(statements)
               if ast.dump(statement, include_attributes=False) == expected]
    return matches[0] if len(matches) == 1 else -1


def calls_named(node: ast.AST, name: str) -> list[ast.Call]:
    return [item for item in ast.walk(node)
            if isinstance(item, ast.Call) and qualified_name(item.func) == name]


def contains_statement(node: ast.AST, source: str) -> bool:
    expected = statement_dump(source)
    return any(
        ast.dump(item, include_attributes=False) == expected
        for item in ast.walk(node)
        if isinstance(item, ast.stmt)
    )


def statement_count(node: ast.AST, source: str) -> int:
    expected = statement_dump(source)
    return sum(
        ast.dump(item, include_attributes=False) == expected
        for item in ast.walk(node)
        if isinstance(item, ast.stmt)
    )


def node_count(node: ast.AST, kind: type[ast.AST]) -> int:
    return sum(isinstance(item, kind) for item in ast.walk(node))


def handler_count(node: ast.AST, name: str) -> int:
    return sum(
        isinstance(item, ast.ExceptHandler)
        and isinstance(item.type, ast.Name)
        and item.type.id == name
        for item in ast.walk(node)
    )


def stored_name_count(node: ast.AST, name: str) -> int:
    return sum(
        isinstance(item, ast.Name)
        and isinstance(item.ctx, ast.Store)
        and item.id == name
        for item in ast.walk(node)
    )


def function_arguments_are(
    node: ast.FunctionDef,
    positional: list[str],
    keyword_only: list[str],
    keyword_defaults: int,
    variadic_keyword: str | None = None,
) -> bool:
    return (
        [item.arg for item in node.args.args] == positional
        and [item.arg for item in node.args.kwonlyargs] == keyword_only
        and len(node.args.kw_defaults) == keyword_defaults
        and node.args.vararg is None
        and (node.args.kwarg.arg if node.args.kwarg is not None else None)
            == variadic_keyword
    )


def single_owned_helper(
    helpers: dict[str, list[ast.FunctionDef]], name: str
) -> ast.FunctionDef | None:
    matches = helpers.get(name, [])
    return matches[0] if len(matches) == 1 else None


def owned_deadline_helper_safe(node: ast.FunctionDef) -> bool:
    expected = ast.dump(ast.parse('''\
def owned_operation_deadline(timeout: float | None) -> float:
    seconds: float | int = (
        MAX_DURATION_MILLISECONDS / 1000.0 if timeout is None else timeout
    )
    if (
        type(seconds) not in (int, float)
        or not 0 <= seconds <= MAX_DURATION_MILLISECONDS / 1000.0
    ):
        raise SupervisorFailure("protocol_failure")
    return time.monotonic() + float(seconds)
''').body[0], include_attributes=False)
    return ast.dump(node, include_attributes=False) == expected


def owned_close_helpers_safe(
    close_one: ast.FunctionDef, close_many: ast.FunctionDef
) -> bool:
    close_one_expected = ast.dump(ast.parse('''\
def owned_close_stream(stream: BinaryIO | None) -> bool:
    if stream is None:
        return True
    try:
        if stream.closed:
            return True
        stream.close()
        return stream.closed
    except BaseException:
        return bool(getattr(stream, "closed", False))
''').body[0], include_attributes=False)
    close_many_expected = ast.dump(ast.parse('''\
def owned_close_streams(streams: Sequence[BinaryIO | None]) -> bool:
    results = [owned_close_stream(stream) for stream in streams]
    return all(results)
''').body[0], include_attributes=False)
    return (
        ast.dump(close_one, include_attributes=False) == close_one_expected
        and ast.dump(close_many, include_attributes=False) == close_many_expected
    )


def owned_capture_helper_safe(node: ast.FunctionDef) -> bool:
    tries = [item for item in node.body if isinstance(item, ast.Try)]
    if (
        not function_arguments_are(node, [
            "stream", "index", "captures", "captured_total", "capture_lock",
            "failure_state", "failure_lock", "abort", "maximum",
        ], [], 0)
        or len(tries) != 1
        or node.body != tries
        or len(calls_named(node, "stream.read")) != 1
        or len(calls_named(node, "captures.extend")) != 0
        or len(calls_named(node, "owned_record_failure")) < 4
        or len(calls_named(node, "owned_observed_failure")) != 1
        or len(calls_named(node, "owned_close_stream")) != 1
        or handler_count(node, "BaseException") != 1
        or handler_count(node, "Exception") != 0
        or node_count(node, ast.Return) != 3
    ):
        return False
    required = [
        "chunk = stream.read(OWNED_RUN_CHUNK_BYTES)",
        "remaining = maximum - captured_total[0]",
        "accepted = min(len(chunk), max(0, remaining))",
        "captures[index].extend(chunk[:accepted])",
        "captured_total[0] += accepted",
        '''if accepted != len(chunk):
            owned_record_failure(
                failure_state, failure_lock,
                "supervisor_output_limit",
            )''',
        '''if owned_observed_failure(failure_state, failure_lock) is not None:
            return''',
        '''if not owned_close_stream(stream) and not abort.is_set():
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )''',
    ]
    capture_with = [item for item in ast.walk(node) if isinstance(item, ast.With)]
    expected_capture_with = statement_dump('''with capture_lock:
    remaining = maximum - captured_total[0]
    accepted = min(len(chunk), max(0, remaining))
    if accepted:
        captures[index].extend(chunk[:accepted])
        captured_total[0] += accepted
    if accepted != len(chunk):
        owned_record_failure(
            failure_state, failure_lock,
            "supervisor_output_limit",
        )''')
    return (
        all(contains_statement(node, source) for source in required)
        and len(tries[0].body) == 1
        and isinstance(tries[0].body[0], ast.While)
        and len(capture_with) == 1
        and qualified_name(capture_with[0].items[0].context_expr) == "capture_lock"
        and ast.dump(capture_with[0], include_attributes=False)
            == expected_capture_with
        and bool(tries[0].finalbody)
    )


def owned_input_helper_safe(node: ast.FunctionDef) -> bool:
    tries = [item for item in node.body if isinstance(item, ast.Try)]
    os_handlers = [
        handler for item in tries for handler in item.handlers
        if isinstance(handler.type, ast.Name) and handler.type.id == "OSError"
    ]
    return (
        function_arguments_are(
            node, ["stream", "payload", "failure_state", "failure_lock", "abort"],
            [], 0
        )
        and len(tries) == 1
        and node.body == tries
        and len(calls_named(node, "stream.write")) == 1
        and len(calls_named(node, "stream.flush")) == 1
        and len(calls_named(node, "owned_close_stream")) == 1
        and len(calls_named(node, "owned_input_closed_early")) == 1
        and len(os_handlers) == 1
        and handler_count(node, "BaseException") == 1
        and handler_count(node, "Exception") == 0
        and node_count(node, ast.Return) == 1
        and len(tries[0].body) == 3
        and isinstance(tries[0].body[0], ast.Assign)
        and isinstance(tries[0].body[1], ast.While)
        and isinstance(tries[0].body[2], ast.If)
        and contains_statement(node,
            "written = stream.write(payload[offset:offset + OWNED_RUN_CHUNK_BYTES])")
        and contains_statement(os_handlers[0], '''if (
            not abort.is_set() and not owned_input_closed_early(error)
        ):
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )''')
        and contains_statement(node, '''if not owned_close_stream(stream) and not abort.is_set():
            owned_record_failure(
                failure_state, failure_lock, "child_wait_failed"
            )''')
        and bool(tries[0].finalbody)
    )


def owned_join_helper_safe(node: ast.FunctionDef) -> bool:
    expected = ast.dump(ast.parse('''\
def owned_join_workers(
    workers: list[threading.Thread], deadline: float, reserve: float = 0.0
) -> bool:
    try:
        while True:
            worker = next((item for item in workers if item.is_alive()), None)
            if worker is None:
                return True
            remaining = owned_remaining(deadline) - reserve
            if remaining <= 0:
                return False
            worker.join(timeout=min(OWNED_RUN_POLL_SECONDS, remaining))
    except BaseException:
        return False
''').body[0], include_attributes=False)
    return ast.dump(node, include_attributes=False) == expected


def timeout_is_remaining(call: ast.Call) -> bool:
    if call.args or len(call.keywords) != 1 or call.keywords[0].arg != "timeout":
        return False
    value = call.keywords[0].value
    return (
        isinstance(value, ast.Call)
        and qualified_name(value.func) == "owned_remaining"
        and len(value.args) == 1
        and isinstance(value.args[0], ast.Name)
        and value.args[0].id == "cleanup_deadline"
    )


def join_uses_cleanup_deadline(call: ast.Call) -> bool:
    return (
        not call.keywords
        and len(call.args) in {2, 3}
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "workers"
        and isinstance(call.args[1], ast.Name)
        and call.args[1].id == "cleanup_deadline"
    )


def owned_failure_helpers_safe(
    record: ast.FunctionDef, observed: ast.FunctionDef,
    input_closed: ast.FunctionDef,
) -> bool:
    expected = ast.parse('''\
def owned_record_failure(
    state: list[tuple[float, str] | None],
    lock: threading.Lock,
    code: str,
    occurred_at: float | None = None,
) -> None:
    timestamp = time.monotonic() if occurred_at is None else occurred_at
    priority = {
        "supervisor_deadline": 0,
        "supervisor_output_limit": 1,
        "child_wait_failed": 2,
    }[code]
    with lock:
        current = state[0]
        if current is None or (timestamp, priority) < (
            current[0], {
                "supervisor_deadline": 0,
                "supervisor_output_limit": 1,
                "child_wait_failed": 2,
            }[current[1]]
        ):
            state[0] = (timestamp, code)

def owned_observed_failure(
    state: list[tuple[float, str] | None], lock: threading.Lock
) -> str | None:
    with lock:
        return state[0][1] if state[0] is not None else None

def owned_input_closed_early(error: OSError) -> bool:
    return isinstance(error, BrokenPipeError) or (
        os.name == "nt"
        and (
            getattr(error, "errno", None) == errno.EINVAL
            or getattr(error, "winerror", None) == 232
        )
    )
''').body
    return all(
        ast.dump(actual, include_attributes=False)
        == ast.dump(wanted, include_attributes=False)
        for actual, wanted in zip(
            (record, observed, input_closed), expected, strict=True
        )
    )


def owned_run_boundary_safe(
    node: ast.FunctionDef, helpers: dict[str, list[ast.FunctionDef]]
) -> bool:
    deadline = single_owned_helper(helpers, "owned_operation_deadline")
    remaining = single_owned_helper(helpers, "owned_remaining")
    close_one = single_owned_helper(helpers, "owned_close_stream")
    close_many = single_owned_helper(helpers, "owned_close_streams")
    record = single_owned_helper(helpers, "owned_record_failure")
    observed = single_owned_helper(helpers, "owned_observed_failure")
    capture = single_owned_helper(helpers, "owned_capture_pipe")
    input_closed = single_owned_helper(helpers, "owned_input_closed_early")
    writer = single_owned_helper(helpers, "owned_write_input")
    joiner = single_owned_helper(helpers, "owned_join_workers")
    if any(item is None for item in (
        deadline, remaining, close_one, close_many, record, observed,
        capture, input_closed, writer, joiner
    )):
        return False
    assert deadline is not None and remaining is not None
    assert close_one is not None and close_many is not None
    assert record is not None and observed is not None and input_closed is not None
    assert capture is not None and writer is not None and joiner is not None
    if (
        not owned_deadline_helper_safe(deadline)
        or ast.dump(remaining, include_attributes=False) != ast.dump(ast.parse('''\
def owned_remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())
''').body[0], include_attributes=False)
        or not owned_close_helpers_safe(close_one, close_many)
        or not owned_failure_helpers_safe(record, observed, input_closed)
        or not owned_capture_helper_safe(capture)
        or not owned_input_helper_safe(writer)
        or not owned_join_helper_safe(joiner)
    ):
        return False
    if not function_arguments_are(
        node, ["argv"], ["timeout", "check", "input", "max_output_bytes"],
        4, "options"
    ):
        return False
    if (
        not isinstance(node.args.kw_defaults[0], ast.Constant)
        or node.args.kw_defaults[0].value is not None
        or not isinstance(node.args.kw_defaults[1], ast.Constant)
        or node.args.kw_defaults[1].value is not False
        or not isinstance(node.args.kw_defaults[2], ast.Constant)
        or node.args.kw_defaults[2].value is not None
        or not isinstance(node.args.kw_defaults[3], ast.Name)
        or node.args.kw_defaults[3].id != "MAX_OUTPUT_BYTES"
    ):
        return False
    if calls_named(node, "child.communicate") or calls_named(node, "communicate"):
        return False
    if calls_named(node, "subprocess.CalledProcessError"):
        return False
    waits = calls_named(node, "child.wait")
    joins = calls_named(node, "owned_join_workers")
    threads = calls_named(node, "threading.Thread")
    operation_loops = [
        item for item in ast.walk(node)
        if isinstance(item, ast.While)
        and ast.dump(item.test, include_attributes=False) == ast.dump(
            ast.parse("failure is None", mode="eval").body,
            include_attributes=False,
        )
    ]
    expected_operation_loop = statement_dump('''while failure is None:
    now = time.monotonic()
    if now >= operation_deadline:
        owned_record_failure(
            failure_state, failure_lock, "supervisor_deadline",
            operation_deadline,
        )
    failure = owned_observed_failure(failure_state, failure_lock)
    if failure is not None:
        break
    if child.poll() is not None:
        break
    time.sleep(min(
        OWNED_RUN_POLL_SECONDS, owned_remaining(operation_deadline)
    ))''')
    if (
        len(calls_named(node, "owned_operation_deadline")) != 1
        or len(calls_named(node, "owned_popen")) != 1
        or len(calls_named(node, "child.kill")) != 2
        or len(waits) != 2
        or not all(timeout_is_remaining(call) for call in waits)
        or len(joins) != 2
        or not all(join_uses_cleanup_deadline(call) for call in joins)
        or len(calls_named(node, "owned_close_streams")) != 3
        or len(calls_named(node, "owned_record_failure")) != 3
        or len(calls_named(node, "owned_observed_failure")) != 3
        or len(calls_named(node, "os._exit")) != 1
        or len(threads) != 3
        or len(operation_loops) != 1
        or ast.dump(operation_loops[0], include_attributes=False)
            != expected_operation_loop
        or stored_name_count(node, "operation_deadline") != 1
        or stored_name_count(node, "cleanup_deadline") != 1
        or stored_name_count(node, "bounded_argv") != 1
        or node_count(node, ast.Return) != 1
        or handler_count(node, "BaseException") != 8
        or any(
            isinstance(handler.type, ast.Name)
            and handler.type.id == "Exception"
            for handler in ast.walk(node)
            if isinstance(handler, ast.ExceptHandler)
        )
    ):
        return False
    thread_targets = [
        qualified_name(next((keyword.value for keyword in call.keywords
                             if keyword.arg == "target"), ast.Constant(None)))
        for call in threads
    ]
    daemon_values = [
        next((keyword.value for keyword in call.keywords
              if keyword.arg == "daemon"), None)
        for call in threads
    ]
    if (
        thread_targets.count("owned_capture_pipe") != 2
        or thread_targets.count("owned_write_input") != 1
        or not all(isinstance(value, ast.Constant) and value.value is True
                   for value in daemon_values)
    ):
        return False
    required = [
        "operation_deadline = owned_operation_deadline(timeout)",
        '''if type(argv) in (str, bytes):
        raise SupervisorFailure("protocol_failure")''',
        '''try:
        bounded_argv = list(argv)
    except BaseException:
        raise SupervisorFailure("protocol_failure") from None''',
        '''if (
        type(max_output_bytes) is not int
        or not 0 <= max_output_bytes <= MAX_OUTPUT_BYTES
        or not bounded_argv
        or any(type(argument) is not str or "\\0" in argument
               for argument in bounded_argv)
        or (input is not None and type(input) is not bytes)
        or any(name in options for name in (
            "encoding", "errors", "text", "universal_newlines"
        ))
        or (input is not None and "stdin" in options)
    ):
        raise SupervisorFailure("protocol_failure")''',
        'captures_stdout = options.get("stdout") is subprocess.PIPE',
        'captures_stderr = options.get("stderr") is subprocess.PIPE',
        "child = owned_popen(bounded_argv, **options)",
        "cleanup_deadline = time.monotonic() + TREE_JOIN_SECONDS",
        '''if failure is not None:
            abort.set()
            try:
                child.kill()
            except BaseException:
                pass''',
        '''if not root_reaped or not workers_joined:
        os._exit(127)''',
        '''if not streams_closed:
        owned_record_failure(
            failure_state, failure_lock, "child_wait_failed"
        )''',
        '''if failure is None:
        failure = owned_observed_failure(failure_state, failure_lock)''',
        '''if failure is not None:
        raise SupervisorFailure(failure)''',
        "stdout = bytes(captures[0]) if captures_stdout else None",
        "stderr = bytes(captures[1]) if captures_stderr else None",
        '''result = subprocess.CompletedProcess(
            bounded_argv, child.returncode, stdout, stderr
        )''',
        "return result",
        '''if check and result.returncode:
        category = windows_abnormal_exit_category(result.returncode)
        raise SupervisorFailure(category or "child_abnormal_exit")''',
    ]
    return (
        all(contains_statement(node, source) for source in required)
        and statement_count(
            node, "root_reaped = child.returncode is not None"
        ) == 2
    )


def owned_check_output_boundary_safe(node: ast.FunctionDef) -> bool:
    expected = ast.dump(ast.parse('''\
def owned_check_output(argv: Sequence[str], *, timeout: float | None = None,
                       max_output_bytes: int = MAX_OUTPUT_BYTES,
                       **options: object) -> bytes:
    options["stdout"] = subprocess.PIPE
    options["stderr"] = subprocess.PIPE
    return owned_run(
        argv, timeout=timeout, check=True,
        max_output_bytes=max_output_bytes, **options
    ).stdout or b""
''').body[0], include_attributes=False)
    return ast.dump(node, include_attributes=False) == expected


WINDOWS_ABNORMAL_EXIT_FORM = ast.dump(ast.parse('''\
def windows_abnormal_exit_category(returncode: int) -> str | None:
    """Map an NTSTATUS exit to a finite, non-sensitive diagnosis."""
    if returncode <= 255:
        return None
    return {
        0xC0000005: "child_access_violation",
        0xC0000008: "child_invalid_handle",
        0xC000000D: "child_invalid_parameter",
        0xC0000017: "child_no_memory",
        0xC000001D: "child_illegal_instruction",
        0xC0000022: "child_access_denied",
        0xC000007B: "child_invalid_image",
        0xC00000FD: "child_stack_overflow",
        0xC000012F: "child_invalid_image",
        0xC0000135: "child_dependency_missing",
        0xC0000139: "child_entrypoint_missing",
        0xC000013A: "child_controlled_interrupt",
        0xC0000142: "child_initialization_failed",
        0xC0000374: "child_heap_corruption",
        0xC0000409: "child_fast_fail",
        0xC0000417: "child_invalid_crt_parameter",
        0xC0000420: "child_assertion_failure",
        0x40000015: "child_fatal_application_exit",
        0xFFFFFFFF: "child_runtime_abort",
    }.get(returncode & 0xFFFFFFFF, "child_abnormal_exit")
''').body[0], include_attributes=False)


PSEUDOCONSOLE_CRITICAL_STATEMENTS = [statement_dump(source) for source in [
    '''result = CREATE_PSEUDO_CONSOLE(
        COORD(240, 80), input_read, output_write, 0,
        ctypes.byref(pseudoconsole)
    )''',
    '''if not close_windows_handle(int(input_read.value or 0)):
        raise SupervisorFailure("console_prestart_cleanup_failed")''',
    '''input_read = wintypes.HANDLE()''',
    '''if not close_windows_handle(int(output_write.value or 0)):
        raise SupervisorFailure("console_prestart_cleanup_failed")''',
    '''output_write = wintypes.HANDLE()''',
    '''descriptor = msvcrt.open_osfhandle(
        int(output_read.value), os.O_RDONLY | os.O_BINARY
    )''',
    '''output_read = wintypes.HANDLE()''',
    '''if fault == "fdopen":
        raise OSError''',
    '''output_stream = os.fdopen(descriptor, "rb", buffering=0)''',
    '''descriptor = -1''',
    '''if not KERNEL32.UpdateProcThreadAttribute(
        attribute_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        ctypes.c_void_p(int(pseudoconsole.value)),
        ctypes.sizeof(ctypes.c_void_p),
        None, None
    ):
        raise SupervisorFailure("console_attribute_failed")''',
    '''startup = STARTUPINFOEX()''',
    '''startup.StartupInfo.cb = ctypes.sizeof(startup)''',
    '''startup.lpAttributeList = attribute_list''',
    '''command_line = ctypes.create_unicode_buffer(
        subprocess.list2cmdline(list(argv))
    )''',
    '''standard_handle_ids = (
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
    )''',
    '''saved_standard_handles: list[int | None] = []''',
    '''cleared_standard_handles = 0''',
    '''restore_failed = False''',
    '''if restore_failed:
        raise SupervisorFailure("console_prestart_setup_failed")''',
    '''if not created:
        raise SupervisorFailure("console_child_start_failed")''',
    '''prestart_reap_confirmed = False''',
    '''assigned_ok = False if fault == "assign" else bool(
        KERNEL32.AssignProcessToJobObject(job, process.hProcess)
    )''',
    '''if not assigned_ok:
        raise SupervisorFailure("job_assign_failed")''',
    '''assigned = True''',
    '''if fault == "postassign":
        raise OSError''',
    '''child = WindowsPseudoConsoleChild(
        argv, process, int(pseudoconsole.value),
        int(input_write.value), output_stream
    )''',
    '''process = PROCESS_INFORMATION()''',
    '''pseudoconsole = wintypes.HANDLE()''',
    '''input_write = wintypes.HANDLE()''',
    '''output_stream = None''',
    '''created = False''',
    '''return child''',
]]


STANDARD_HANDLE_CREATE_FORM = ast.dump(ast.parse('''\
try:
    for standard_handle_id in standard_handle_ids:
        saved_standard_handles.append(
            KERNEL32.GetStdHandle(standard_handle_id)
        )
        if not KERNEL32.SetStdHandle(
            standard_handle_id, wintypes.HANDLE()
        ):
            raise SupervisorFailure("console_prestart_setup_failed")
        cleared_standard_handles += 1
    created = bool(KERNEL32.CreateProcessW(
        argv[0], command_line, None, None, False,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
        | CREATE_SUSPENDED,
        None, None, ctypes.byref(startup.StartupInfo),
        ctypes.byref(process)
    ))
finally:
    for index in range(cleared_standard_handles):
        restored = saved_standard_handles[index]
        if not KERNEL32.SetStdHandle(
            standard_handle_ids[index],
            wintypes.HANDLE(restored or 0),
        ):
            restore_failed = True
''').body[0], include_attributes=False)


PSEUDOCONSOLE_FINAL_STATEMENTS = [statement_dump(source) for source in [
    '''if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError:
            cleanup_failed = True''',
    '''if created and not prestart_reap_confirmed:
        raise SupervisorFailure("prestart_reap_unconfirmed")''',
    '''if cleanup_failed:
        raise SupervisorFailure("console_prestart_cleanup_failed")''',
]]


PRE_RESUME_CLOSE_FORM = structural_function_dump(ast.parse('''\
def close_console_before_resume(self) -> bool:
    """Close a ConPTY whose suspended client never executed user code.

    The no-drain close is restricted to this state: no client instruction
    ran, so it cannot have produced pending pseudoconsole output.  Once
    ResumeThread succeeds every cleanup path must use the concurrent drain
    in close_console_while_draining instead.
    """
    if self._resumed or self._console_close_started:
        return False
    self._console_close_started = True
    closed = close_windows_handle(self._input_write)
    if closed:
        self._input_write = 0
    try:
        if CLOSE_PSEUDO_CONSOLE is not None and self._pseudoconsole:
            CLOSE_PSEUDO_CONSOLE(wintypes.HANDLE(self._pseudoconsole))
            self._pseudoconsole = 0
            self._console_closed = True
    except Exception:
        self._console_closed = False
    try:
        self.stdout.close()
    except OSError:
        closed = False
    self._console_close_completed.set()
    return closed and self._console_closed
''').body[0])


RESUME_FORM = ast.dump(ast.parse('''\
def resume(self) -> None:
    if not self._thread:
        raise SupervisorFailure("job_resume_failed")
    result = KERNEL32.ResumeThread(wintypes.HANDLE(self._thread))
    if result == 0xFFFFFFFF:
        raise SupervisorFailure("job_resume_failed")
    self._resumed = True
    thread_closed = close_windows_handle(self._thread)
    if thread_closed:
        self._thread = 0
    if not thread_closed:
        raise SupervisorFailure("console_prestart_cleanup_failed")
''').body[0], include_attributes=False)


CONSOLE_DRAIN_CLOSE_FORM = structural_function_dump(ast.parse('''\
def close_console_while_draining(
    self, relay: threading.Thread
) -> bool:
    """Close ConPTY while its output reader remains active.

    Microsoft documents that ClosePseudoConsole can block when output is
    not drained.  The relay is therefore started before the workload and
    remains active during close.  Both operations must finish before the
    completion attestation can be emitted.
    """
    input_closed = close_windows_handle(self._input_write)
    if input_closed:
        self._input_write = 0
    if not self._console_close_started:
        self._console_close_started = True

        def close_console() -> None:
            try:
                if CLOSE_PSEUDO_CONSOLE is not None:
                    CLOSE_PSEUDO_CONSOLE(
                        wintypes.HANDLE(self._pseudoconsole)
                    )
                    self._pseudoconsole = 0
                    self._console_closed = True
            except Exception:
                self._console_closed = False
            finally:
                self._console_close_completed.set()

        closer = threading.Thread(target=close_console, daemon=True)
        closer.start()
    relay.join(timeout=TREE_JOIN_SECONDS)
    self._console_close_completed.wait(timeout=TREE_JOIN_SECONDS)
    complete = input_closed and self._console_closed and not relay.is_alive()
    if complete:
        try:
            self.stdout.close()
        except OSError:
            complete = False
    return complete
''').body[0])


PROCESS_HANDLE_CLOSE_FORM = ast.dump(ast.parse('''\
def close_process_handles(self) -> bool:
    if self._process_handles_closed:
        return True
    for attribute in ("_thread", "_handle", "_input_write"):
        handle = int(getattr(self, attribute))
        if handle and close_windows_handle(handle):
            setattr(self, attribute, 0)
    self._process_handles_closed = not any(
        (self._thread, self._handle, self._input_write)
    )
    return self._process_handles_closed
''').body[0], include_attributes=False)


OUTPUT_RELAY_FORM = ast.dump(ast.parse('''\
def output_relay(
    stream: BinaryIO,
    output_limited: threading.Event,
    protocol_failed: threading.Event,
    limit: int,
) -> None:
    count = 0
    forwarding = True
    try:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                return
            count = min(limit + 1, count + len(chunk))
            if count > limit:
                output_limited.set()
                forwarding = False
            if forwarding:
                try:
                    write_packet(b"O" + chunk)
                except (BrokenPipeError, OSError, SupervisorFailure):
                    protocol_failed.set()
                    forwarding = False
    except Exception:
        protocol_failed.set()
''').body[0], include_attributes=False)


CONSOLE_ATTACHMENT_FORM = ast.dump(ast.parse('''\
def windows_console_attached() -> bool:
    if not KERNEL32.GetConsoleOutputCP():
        return False
    in_job = wintypes.BOOL()
    if not KERNEL32.IsProcessInJob(
        KERNEL32.GetCurrentProcess(), None, ctypes.byref(in_job)
    ) or not in_job.value:
        return False
    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    if not KERNEL32.QueryInformationJobObject(
        None,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
        None,
    ):
        return False
    return bool(
        limits.BasicLimitInformation.LimitFlags
        & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
''').body[0], include_attributes=False)


def pre_resume_close_boundary_safe(node: ast.FunctionDef) -> bool:
    return structural_function_dump(node) == PRE_RESUME_CLOSE_FORM


def resume_boundary_safe(node: ast.FunctionDef) -> bool:
    return ast.dump(node, include_attributes=False) == RESUME_FORM


def console_drain_close_boundary_safe(node: ast.FunctionDef) -> bool:
    return structural_function_dump(node) == CONSOLE_DRAIN_CLOSE_FORM


def process_handle_close_boundary_safe(node: ast.FunctionDef) -> bool:
    return ast.dump(node, include_attributes=False) == PROCESS_HANDLE_CLOSE_FORM


def output_relay_boundary_safe(node: ast.FunctionDef) -> bool:
    return ast.dump(node, include_attributes=False) == OUTPUT_RELAY_FORM


def console_attachment_boundary_safe(node: ast.FunctionDef) -> bool:
    return ast.dump(node, include_attributes=False) == CONSOLE_ATTACHMENT_FORM


def pseudoconsole_boundary_safe(node: ast.FunctionDef) -> bool:
    arguments = node.args
    if ([item.arg for item in arguments.args] != ["argv", "job"]
            or [item.arg for item in arguments.kwonlyargs] != ["fault"]
            or len(arguments.kw_defaults) != 1
            or not isinstance(arguments.kw_defaults[0], ast.Constant)
            or arguments.kw_defaults[0].value is not None
            or arguments.vararg is not None or arguments.kwarg is not None
            or arguments.defaults):
        return False
    top_level_tries = [item for item in node.body if isinstance(item, ast.Try)]
    if len(top_level_tries) != 1 or node.body[-1] is not top_level_tries[0]:
        return False
    boundary = top_level_tries[0]
    if len(boundary.handlers) != 2 or boundary.orelse:
        return False
    indexes = [direct_statement_index(boundary.body, expected)
               for expected in PSEUDOCONSOLE_CRITICAL_STATEMENTS]
    if any(index < 0 for index in indexes) or indexes != sorted(indexes):
        return False
    if indexes[-1] != len(boundary.body) - 1:
        return False
    standard_handle_tries = [
        (index, statement)
        for index, statement in enumerate(boundary.body)
        if (isinstance(statement, ast.Try)
            and ast.dump(statement, include_attributes=False)
            == STANDARD_HANDLE_CREATE_FORM)
    ]
    if len(standard_handle_tries) != 1:
        return False
    standard_try_index, standard_try = standard_handle_tries[0]
    restore_setup_index = direct_statement_index(
        boundary.body, statement_dump("restore_failed = False")
    )
    restore_check_index = direct_statement_index(
        boundary.body, statement_dump('''if restore_failed:
            raise SupervisorFailure("console_prestart_setup_failed")''')
    )
    child_check_index = direct_statement_index(
        boundary.body, statement_dump('''if not created:
            raise SupervisorFailure("console_child_start_failed")''')
    )
    if (standard_try_index != restore_setup_index + 1
            or restore_check_index != standard_try_index + 1
            or child_check_index != restore_check_index + 1):
        return False
    create_calls = calls_named(boundary, "KERNEL32.CreateProcessW")
    attribute_calls = calls_named(
        boundary, "KERNEL32.UpdateProcThreadAttribute"
    )
    assign_calls = calls_named(boundary, "KERNEL32.AssignProcessToJobObject")
    fdopen_calls = calls_named(boundary, "os.fdopen")
    descriptor_calls = calls_named(boundary, "msvcrt.open_osfhandle")
    if (len(create_calls) != 1 or len(assign_calls) != 1
            or len(attribute_calls) != 1
            or len(fdopen_calls) != 1 or len(descriptor_calls) != 1
            or len(calls_named(standard_try, "KERNEL32.CreateProcessW")) != 1
            or len(calls_named(standard_try, "KERNEL32.GetStdHandle")) != 1
            or len(calls_named(standard_try, "KERNEL32.SetStdHandle")) != 2
            or not pseudoconsole_create_call_safe(create_calls[0])
            or not pseudoconsole_attribute_call_safe(attribute_calls[0])):
        return False
    final_indexes = [direct_statement_index(boundary.finalbody, expected)
                     for expected in PSEUDOCONSOLE_FINAL_STATEMENTS]
    if any(index < 0 for index in final_indexes):
        return False
    if final_indexes != sorted(final_indexes):
        return False
    final_tree = ast.Module(body=boundary.finalbody, type_ignores=[])
    required_final_calls = {
        "KERNEL32.TerminateJobObject": 1,
        "KERNEL32.TerminateProcess": 1,
        "KERNEL32.WaitForSingleObject": 1,
        "windows_active_processes": 1,
        "CLOSE_PSEUDO_CONSOLE": 1,
        "os.close": 1,
        "output_stream.close": 1,
    }
    if any(len(calls_named(final_tree, name)) != count
           for name, count in required_final_calls.items()):
        return False
    # The exact critical statements above are direct members of this single try, and the call counts are one.
    # A correct-looking dead-branch duplicate therefore cannot mask a different operational launch or assignment.
    return True


def fixed_failure_raise(statement: ast.stmt, code: str) -> bool:
    return (
        isinstance(statement, ast.Raise)
        and isinstance(statement.exc, ast.Call)
        and qualified_name(statement.exc.func) == "SupervisorFailure"
        and len(statement.exc.args) == 1
        and isinstance(statement.exc.args[0], ast.Constant)
        and statement.exc.args[0].value == code
    )


def posix_supervisor_boundary_safe(node: ast.FunctionDef) -> bool:
    if [item.arg for item in node.args.args] != ["argv", "deadline", "output_limit"]:
        return False
    boundaries = [item for item in node.body if isinstance(item, ast.Try)]
    if len(boundaries) != 1 or node.body[-1] is not boundaries[0]:
        return False
    boundary = boundaries[0]
    spawn_tries = [item for item in boundary.body if isinstance(item, ast.Try)
                   and calls_named(item, "owned_popen")]
    if len(spawn_tries) != 1:
        return False
    spawn_try = spawn_tries[0]
    if (len(calls_named(spawn_try, "owned_popen")) != 1
            or len(spawn_try.handlers) != 1
            or not isinstance(spawn_try.handlers[0].type, ast.Name)
            or spawn_try.handlers[0].type.id != "OSError"
            or len(spawn_try.handlers[0].body) != 1
            or not fixed_failure_raise(
                spawn_try.handlers[0].body[0], "child_start_failed")):
        return False
    if not boundary.finalbody:
        return False
    final_tree = ast.Module(body=boundary.finalbody, type_ignores=[])
    if (len(calls_named(final_tree, "terminate_posix_group")) < 2
            or len(calls_named(final_tree, "posix_group_exists")) < 2
            or len(calls_named(final_tree, "child.wait")) != 1
            or len(calls_named(final_tree, "relay.join")) != 1
            or len(calls_named(final_tree, "os._exit")) != 1):
        return False
    relay_exit = statement_dump('''if relay.is_alive():
        os._exit(127)''')
    if not any(
        ast.dump(candidate, include_attributes=False) == relay_exit
        for candidate in ast.walk(final_tree)
        if isinstance(candidate, ast.If)
    ):
        return False
    cleanup_branches = [item for item in boundary.finalbody
                        if (isinstance(item, ast.If)
                            and ast.dump(item.test, include_attributes=False)
                            == ast.dump(ast.parse(
                                "child is not None", mode="eval"
                            ).body, include_attributes=False))]
    if (len(cleanup_branches) != 1
            or boundary.finalbody[-1] is not cleanup_branches[0]
            or cleanup_branches[0].orelse):
        return False
    expected_final = statement_dump('''if not cleanup_confirmed:
        raise SupervisorFailure("group_reap_unconfirmed")''')
    cleanup_body = cleanup_branches[0].body
    return direct_statement_index(cleanup_body, expected_final) == len(cleanup_body) - 1


def windows_supervisor_boundary_safe(node: ast.FunctionDef) -> bool:
    if [item.arg for item in node.args.args] != ["argv", "deadline", "output_limit"]:
        return False
    boundaries = [item for item in node.body if isinstance(item, ast.Try)]
    if len(boundaries) != 1 or node.body[-1] is not boundaries[0]:
        return False
    boundary = boundaries[0]
    critical = [statement_dump(source) for source in [
        '''child = create_windows_pseudoconsole_child(argv, job)''',
        '''relay_candidate.start()''',
        '''relay = relay_candidate''',
        '''child.resume()''',
    ]]
    indexes = [direct_statement_index(boundary.body, expected)
               for expected in critical]
    if any(index < 0 for index in indexes) or indexes != sorted(indexes):
        return False
    if not boundary.finalbody:
        return False
    final_tree = ast.Module(body=boundary.finalbody, type_ignores=[])
    if (len(calls_named(final_tree, "KERNEL32.TerminateJobObject")) < 2
            or len(calls_named(final_tree, "windows_active_processes")) < 3
            or len(calls_named(final_tree, "child.wait")) != 1
            or len(calls_named(final_tree, "child.close_process_handles")) != 1
            or len(calls_named(final_tree, "close_windows_handle")) != 1
            or len(calls_named(final_tree, "os._exit")) != 1):
        return False
    expected_final = statement_dump('''if not cleanup_confirmed:
        os._exit(127)''')
    return direct_statement_index(boundary.finalbody, expected_final) >= 0


def source_paths() -> list[Path]:
    paths = sorted({path for root in ROOTS if root.is_dir() for path in root.rglob("*.py")})
    if not 0 < len(paths) <= MAX_FILES:
        raise RuntimeError("invalid_source_count")
    return paths


def audit_source(path: str, source: str) -> Audit:
    tree = ast.parse(source, filename="<authored-source>")
    assigned = {node.id for node in ast.walk(tree)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
    assigned.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    assigned.update(node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    audit = Audit(path, assigned)
    audit.visit(tree)
    audit.validate_boundary()
    return audit


def run_audit() -> int:
    paths = source_paths()
    launches: list[dict[str, object]] = []
    unsafe: list[dict[str, object]] = []
    digest = hashlib.sha256()
    for path in paths:
        data = path.read_bytes()
        if len(data) > MAX_BYTES:
            raise RuntimeError("source_too_large")
        relative = path.as_posix()
        digest.update(relative.encode("utf-8") + b"\0" + data + b"\0")
        result = audit_source(relative, data.decode("utf-8"))
        launches.extend(result.launches)
        unsafe.extend(result.unsafe)
    report = {
        "schema": 1,
        "source_files": len(paths),
        "source_sha256": digest.hexdigest(),
        "launches": launches,
        "unsafe": unsafe,
        "passed": not unsafe,
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


def self_test() -> int:
    cases = [
        ("import subprocess\nsubprocess.Popen(['x'], start_new_session=True, close_fds=True)\n", 1),
        ("import subprocess as sp\nsp.run(['x'])\n", 1),
        ("from subprocess import Popen as launch\nlaunch(['x'])\n", 1),
        ("import subprocess\nsubprocess." + chr(92) + "\n Popen(['x'])\n", 1),
        ("import asyncio as aio\naio.create_subprocess_exec('x')\n", 1),
        ("from asyncio import create_subprocess_shell as launch\nlaunch('x')\n", 1),
        ("import os\nos.popen('x')\n", 1),
        ("from os import system as launch\nlaunch('x')\n", 1),
        ("import subprocess\nsubprocess.getoutput('x')\n", 1),
        ("import subprocess\nsubprocess.Popen('x', shell=True)\n", 2),
        ("# subprocess.Popen(['x'])\nnote = \"os.system('x')\"\n", 0),
        ("from process_supervisor import owned_run\nowned_run(['x'], max_output_bytes=1)\n", 0),
        ("from process_supervisor import owned_run\nowned_run(['x'])\n", 1),
        ("from process_supervisor import owned_run\nowned_run(['x'], max_output_bytes=-1)\n", 1),
        ("from process_supervisor import owned_run\nowned_run(['x'], max_output_bytes=True)\n", 1),
        ("from process_supervisor import owned_run\nowned_run(['x'], max_output_bytes=16777217)\n", 1),
        ("import process_supervisor as ps\nps.owned_check_output(['x'], max_output_bytes=0)\n", 0),
        ("import process_supervisor as ps\nps.owned_check_output(['x'], max_output_bytes=1, **{})\n", 1),
        ("from process_supervisor import owned_popen\nowned_popen(['x'])\n", 0),
        ("from fake_process_supervisor import owned_run\nowned_run(['x'])\n", 1),
        ("from process_supervisor import owned_run\nowned_run=lambda x:None\nowned_run(['x'])\n", 1),
        ("def f():\n KERNEL32.CreateProcessW(None,None,None,None,False,0,"
         "None,None,None,None)\n", 1),
    ]
    for source, expected in cases:
        result = audit_source("fixture.py", source)
        if len(result.unsafe) != expected:
            raise AssertionError("python_ast_mutant_not_detected")
    supervisor_source = Path("scripts/process_supervisor.py").read_text(
        encoding="utf-8"
    )
    result = audit_source("scripts/process_supervisor.py", supervisor_source)
    if result.unsafe or len(result.launches) != 2:
        raise AssertionError("pinned_supervisor_rejected")
    boundary_mutants = [
        supervisor_source.replace(
            'options["close_fds"] = True', 'options["close_fds"] = False', 1
        ),
        supervisor_source.replace('if requested != 0:', 'if requested < 0:', 1),
        supervisor_source.replace('not windows_console_attached()', 'True', 1),
        supervisor_source.replace(
            'options["creationflags"] = requested',
            'options["creationflags"] = WINDOWS_CREATE_NO_WINDOW', 1
        ),
        supervisor_source.replace(
            'options["start_new_session"] = supervisor_root',
            'options["start_new_session"] = False', 1
        ),
        supervisor_source.replace('options.get("shell") is True', 'False', 1),
    ]
    for mutant in boundary_mutants:
        if mutant == supervisor_source:
            raise AssertionError("owned_boundary_mutant_not_applied")
        if not audit_source("scripts/process_supervisor.py", mutant).unsafe:
            raise AssertionError("owned_boundary_mutant_not_detected")
    owned_run_mutants = [
        supervisor_source.replace(
            "MAX_DURATION_MILLISECONDS / 1000.0 if timeout is None else timeout",
            "float('inf') if timeout is None else timeout", 1),
        supervisor_source.replace(
            "        bounded_argv = list(argv)",
            "        bounded_argv = argv", 1),
        supervisor_source.replace(
            "    if type(argv) in (str, bytes):",
            "    if False:", 1),
        supervisor_source.replace(
            "chunk = stream.read(OWNED_RUN_CHUNK_BYTES)",
            "chunk = stream.read()", 1),
        supervisor_source.replace(
            "    try:\n"
            "        while not abort.is_set():\n"
            "            chunk = stream.read(OWNED_RUN_CHUNK_BYTES)",
            "    try:\n"
            "        return\n"
            "        while not abort.is_set():\n"
            "            chunk = stream.read(OWNED_RUN_CHUNK_BYTES)",
            1),
        supervisor_source.replace(
            "        while True:\n"
            "            worker = next((item for item in workers if item.is_alive()), None)",
            "        while True:\n"
            "            remaining = owned_remaining(deadline) - reserve\n"
            "            worker = next((item for item in workers if item.is_alive()), None)",
            1),
        supervisor_source.replace(
            "accepted = min(len(chunk), max(0, remaining))",
            "accepted = len(chunk)", 1),
        supervisor_source.replace(
            "    except BaseException:\n"
            "        return bool(getattr(stream, \"closed\", False))",
            "    except Exception:\n"
            "        return bool(getattr(stream, \"closed\", False))",
            1),
        supervisor_source.replace(
            '                        "supervisor_output_limit",',
            '                        "child_wait_failed",', 1),
        supervisor_source.replace(
            "if current is None or (timestamp, priority) < (",
            "if current is None or (timestamp, priority) > (", 1),
        supervisor_source.replace("            child.kill()",
                                  "            child.poll()", 1),
        supervisor_source.replace(
            "child.wait(timeout=owned_remaining(cleanup_deadline))",
            "child.wait()", 1),
        supervisor_source.replace(
            "        streams_closed = owned_close_streams(streams)",
            "        streams_closed = True", 1),
        supervisor_source.replace(
            "    workers_joined = owned_join_workers(\n"
            "        workers, cleanup_deadline, OWNED_RUN_CLOSE_RESERVE_SECONDS\n"
            "    )",
            "    workers_joined = True", 1),
        supervisor_source.replace(
            "    if failure is None:\n"
            "        failure = owned_observed_failure(failure_state, failure_lock)",
            "    if False:\n"
            "        failure = owned_observed_failure(failure_state, failure_lock)",
            1),
        supervisor_source.replace(
            "    if not streams_closed:\n"
            "        owned_record_failure(\n"
            "            failure_state, failure_lock, \"child_wait_failed\"\n"
            "        )",
            "    if not streams_closed:\n"
            "        raise SupervisorFailure(\"child_wait_failed\")",
            1),
        supervisor_source.replace(
            "        while failure is None:\n"
            "            now = time.monotonic()",
            "        while failure is None:\n"
            "            operation_deadline = time.monotonic() + 1.0\n"
            "            now = time.monotonic()",
            1),
        supervisor_source.replace(
            "    cleanup_deadline = time.monotonic() + TREE_JOIN_SECONDS",
            "    cleanup_deadline = time.monotonic() + TREE_JOIN_SECONDS\n"
            "    cleanup_deadline = time.monotonic() + TREE_JOIN_SECONDS",
            1),
        supervisor_source.replace(
            "        if (\n"
            "            not abort.is_set() and not owned_input_closed_early(error)\n"
            "        ):",
            "        if False:", 1),
        supervisor_source.replace(
            "    try:\n"
            "        offset = 0\n"
            "        while offset < len(payload) and not abort.is_set():",
            "    try:\n"
            "        offset = 0\n"
            "        return\n"
            "        while offset < len(payload) and not abort.is_set():",
            1),
        supervisor_source.replace(
            "    except BaseException:\n"
            "        raise SupervisorFailure(\"child_start_failed\") from None",
            "    except Exception:\n"
            "        raise SupervisorFailure(\"child_start_failed\") from None",
            1),
        supervisor_source.replace(
            "            root_reaped = child.returncode is not None",
            "            root_reaped = True", 1),
        supervisor_source.replace(
            "    results = [owned_close_stream(stream) for stream in streams]",
            "    results = [True for stream in streams]", 1),
        supervisor_source.replace(
            "    if not root_reaped or not workers_joined:\n"
            "        # Returning would let an unconfirmed root or pipe owner escape the\n"
            "        # enclosing Job/process-group boundary.  Exiting makes that owner tear\n"
            "        # down the complete native tree before it can attest completion.\n"
            "        os._exit(127)",
            "    if not root_reaped or not workers_joined:\n"
            "        raise SupervisorFailure(\"child_wait_failed\")", 1),
        supervisor_source.replace(
            '        raise SupervisorFailure(category or "child_abnormal_exit")',
            '        raise subprocess.CalledProcessError(result.returncode, argv)',
            1),
        supervisor_source.replace(
            '    options["stderr"] = subprocess.PIPE',
            '    options["stderr"] = None', 1),
    ]
    for mutant_index, mutant in enumerate(owned_run_mutants):
        if mutant == supervisor_source:
            raise AssertionError((
                "owned_run_mutant_not_applied", mutant_index
            ))
        if not audit_source("scripts/process_supervisor.py", mutant).unsafe:
            raise AssertionError((
                "owned_run_mutant_not_detected", mutant_index
            ))
    conpty_result = audit_source(
        "scripts/process_supervisor.py", supervisor_source
    )
    if conpty_result.unsafe or len(conpty_result.launches) != 2:
        raise AssertionError("pseudoconsole_boundary_rejected")
    conpty_mutants = [
        supervisor_source.replace(
            "            ctypes.c_void_p(int(pseudoconsole.value)),\n"
            "            ctypes.sizeof(ctypes.c_void_p),",
            "            ctypes.byref(pseudoconsole),\n"
            "            ctypes.sizeof(ctypes.c_void_p),", 1),
        supervisor_source.replace(
            "            ctypes.sizeof(ctypes.c_void_p),\n"
            "            None, None",
            "            ctypes.sizeof(pseudoconsole),\n"
            "            None, None", 1),
        supervisor_source.replace(
            "            STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE\n",
            "            STD_INPUT_HANDLE, STD_OUTPUT_HANDLE\n", 1),
        supervisor_source.replace(
            "                    standard_handle_id, wintypes.HANDLE()\n",
            "                    standard_handle_id, wintypes.HANDLE(1)\n", 1),
        supervisor_source.replace(
            "                cleared_standard_handles += 1\n"
            "            created = bool(KERNEL32.CreateProcessW(",
            "                cleared_standard_handles += 1\n"
            "            saved_standard_handles = list(saved_standard_handles)\n"
            "            created = bool(KERNEL32.CreateProcessW(", 1),
        supervisor_source.replace(
            "        finally:\n"
            "            for index in range(cleared_standard_handles):",
            "        except Exception:\n"
            "            for index in range(cleared_standard_handles):", 1),
        supervisor_source.replace(
            "        if thread_closed:\n"
            "            self._thread = 0\n"
            "        # Keep the host input writer alive",
            "        if thread_closed:\n"
            "            self._thread = 0\n"
            "        close_windows_handle(self._input_write)\n"
            "        # Keep the host input writer alive", 1),
        supervisor_source.replace(
            '    }.get(returncode & 0xFFFFFFFF, "child_abnormal_exit")',
            '    }.get(returncode & 0xFFFFFFFF, '
            'f"child_abnormal_exit_{returncode}")', 1),
        supervisor_source.replace(
            "| CREATE_SUSPENDED,\n                None, None,",
            "| CREATE_NO_WINDOW,\n                None, None,", 1),
        supervisor_source.replace(
            "ctypes.byref(startup.StartupInfo),\n                ctypes.byref(process)",
            "other_startup,\n                ctypes.byref(process)", 1),
        supervisor_source.replace(
            "                argv[0], command_line, None, None, False,",
            "                other_executable, command_line, None, None, False,", 1),
        supervisor_source.replace(
            "KERNEL32.AssignProcessToJobObject(job, process.hProcess)",
            "KERNEL32.AssignProcessToJobObject(other_job, process.hProcess)", 1),
        supervisor_source.replace(
            "KERNEL32.AssignProcessToJobObject(job, process.hProcess)",
            "KERNEL32.AssignProcessToJobObject(job, other_process)", 1),
        supervisor_source.replace(
            'output_stream = os.fdopen(descriptor, "rb", buffering=0)',
            'output_stream = io.open(descriptor, "rb", buffering=0)', 1),
        supervisor_source.replace(
            'if not close_windows_handle(int(input_read.value or 0)):',
            'if False:', 1),
        supervisor_source.replace(
            'if not close_windows_handle(int(output_write.value or 0)):',
            'if False:', 1),
        supervisor_source.replace(
            "                os.close(descriptor)",
            "                descriptor = descriptor", 1),
        supervisor_source.replace(
            "if self._resumed or self._console_close_started:",
            "if False:", 1),
        supervisor_source.replace(
            "        assigned = True\n        if fault == \"postassign\":",
            "        assigned = False\n        if fault == \"postassign\":", 1),
        supervisor_source.replace(
            "        prestart_reap_confirmed = False\n        assigned_ok =",
            "        prestart_reap_confirmed = True\n        assigned_ok =", 1),
        supervisor_source.replace(
            "        process = PROCESS_INFORMATION()\n        pseudoconsole = wintypes.HANDLE()",
            "        process = process\n        pseudoconsole = wintypes.HANDLE()", 1),
        supervisor_source.replace(
            "        created = False\n        return child",
            "        return child", 1),
        supervisor_source.replace(
            "                output_limited.set()\n                forwarding = False",
            "                output_limited.set()\n                return", 1),
        supervisor_source.replace(
            "        relay.join(timeout=TREE_JOIN_SECONDS)\n"
            "        self._console_close_completed.wait(timeout=TREE_JOIN_SECONDS)",
            "        self._console_close_completed.wait(timeout=TREE_JOIN_SECONDS)\n"
            "        relay.join(timeout=TREE_JOIN_SECONDS)", 1),
        supervisor_source.replace(
            "        input_closed = close_windows_handle(self._input_write)\n"
            "        if input_closed:\n"
            "            self._input_write = 0",
            "        input_closed = True\n"
            "        self._input_write = 0", 1),
        supervisor_source.replace(
            '        for attribute in ("_thread", "_handle", "_input_write"):',
            '        for attribute in ("_thread",):', 1),
        supervisor_source.replace(
            "        if thread_closed:\n            self._thread = 0",
            "        self._thread = 0", 1),
        supervisor_source.replace(
            "    if not KERNEL32.GetConsoleOutputCP():",
            "    if False:", 1),
        supervisor_source.replace(
            "    except SupervisorFailure as failure:\n"
            "        # Only exact pre-child failures may publish a final tree-empty frame.",
            "    except OSError:\n"
            "        status, tree_empty, outlived, requested, console_isolated = "
            "(127, True, False, False, True)\n"
            "    except SupervisorFailure as failure:\n"
            "        # Only exact pre-child failures may publish a final tree-empty frame.",
            1),
        supervisor_source.replace(
            "                if relay.is_alive():\n"
            "                    # A relay blocked on the parent protocol pipe may own",
            "                if relay.is_alive() and cleanup_confirmed:\n"
            "                    # A relay blocked on the parent protocol pipe may own",
            1),
        supervisor_source.replace(
            "            if not cleanup_confirmed:\n"
            "                raise SupervisorFailure(\"group_reap_unconfirmed\")",
            "            if False:\n"
            "                raise SupervisorFailure(\"group_reap_unconfirmed\")",
            1),
    ]
    for mutant_index, mutant in enumerate(conpty_mutants):
        if mutant == supervisor_source:
            raise AssertionError((
                "pseudoconsole_mutant_not_applied", mutant_index
            ))
        if not audit_source("scripts/process_supervisor.py", mutant).unsafe:
            raise AssertionError((
                "pseudoconsole_mutant_not_detected", mutant_index
            ))
    fixture_safe = '''\
from pathlib import Path
import subprocess
import sys
import time
from process_supervisor import owned_run, windows_console_attached
def leaf() -> int:
    if not windows_console_attached():
        return 1
    sys.stdout.buffer.write(b"console_attached=true\\n")
    sys.stdout.buffer.flush()
    time.sleep(0.25)
    return 0
def root() -> int:
    if not windows_console_attached():
        return 1
    result = owned_run(
        [sys.executable, "-E", "-s", "-B", str(Path(__file__)), "--leaf"],
        timeout=5.0,
        max_output_bytes=64,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0 or result.stdout != b"console_attached=true\\n":
        return 1
    sys.stdout.buffer.write(
        b"console_inheritance_fixture passed=true generations=2\\n"
    )
    sys.stdout.buffer.flush()
    return 0
'''
    fixture_result = audit_source(
        "scripts/process_console_inheritance_fixture.py", fixture_safe)
    if fixture_result.unsafe or len(fixture_result.launches) != 1:
        raise AssertionError("console_inheritance_fixture_rejected")
    for mutant in [
        fixture_safe.replace("not windows_console_attached()", "False", 1),
        fixture_safe.replace('"--leaf"', '"--different"'),
        fixture_safe.replace("    time.sleep(0.25)\n", "", 1),
    ]:
        if not audit_source(
            "scripts/process_console_inheritance_fixture.py", mutant
        ).unsafe:
            raise AssertionError("console_inheritance_mutant_not_detected")
    sys.stdout.buffer.write(
        b"windows_console_python_audit self_test passed=true controls=74\n"
    )
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        raise SystemExit(self_test())
    if sys.argv[1:] == ["--audit"]:
        raise SystemExit(run_audit())
    raise SystemExit(2)
