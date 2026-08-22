#!/usr/bin/env python3
"""Checks what a Windows compiler would see, without a Windows compiler.

Three rounds of this project's CI were spent discovering, one forty-minute
matrix run at a time, that a file did not compile on Windows: first the min/max
macros, then POSIX headers in the test suite, then `IN` and `OUT` as macros,
then a `#if !defined(_WIN32)` guard that excluded a namespace's closing brace
and left it open. Every one of those is visible from a Linux or macOS checkout
in under a second, which is what this does.

It resolves only the `_WIN32` conditionals — everything else is left in place,
because the point is the platform view rather than a full preprocessor — and
then reports:

  * unbalanced braces, parentheses or brackets in the Windows view,
  * POSIX-only headers or calls that survive into it,
  * identifiers that Windows defines as macros, used where the preprocessor
    would eat them.

Exit status is non-zero if anything is found. Run it from the repository root.
"""

import glob
import re
import sys

# Identifiers that windows.h and its companions define as function-like or
# object-like macros. An `enum class` is no protection: the preprocessor runs
# first, so `enum class E { IN, OUT }` becomes `enum class E { , }`.
WINDOWS_MACROS = {
    "IN", "OUT", "ERROR", "DELETE", "NEAR", "FAR", "CONST", "OPTIONAL", "NO_ERROR",
    "TRUE", "FALSE", "min", "max", "small", "interface", "ABSOLUTE", "RELATIVE",
    "DOMAIN", "IGNORE", "STRICT", "OVERFLOW", "UNDERFLOW", "DIFFERENCE", "PURE",
    "VOID", "CALLBACK", "INFINITE", "THIS", "RGB",
}

POSIX_HEADERS = re.compile(r'#\s*include\s*<(arpa/[^>]+|sys/[^>]+|netinet/[^>]+|netdb\.h|unistd\.h|pthread\.h|poll\.h|termios\.h)>')

POSIX_CALLS = re.compile(
    r'\b(socket|bind|listen|accept|inet_pton|inet_ntop|setsockopt|getsockname|getaddrinfo|'
    r'pthread_[a-z_]+|sigemptyset|sigaddset|sigwait|sigpending|fork|execve|dup2|pipe)\s*\('
)


PLATFORM = {"_WIN32": True, "_WIN64": True, "__APPLE__": False, "__linux__": False,
            "__EMSCRIPTEN__": False, "__unix__": False, "__FreeBSD__": False}


def evaluate(condition):
    """True, False, or None when the condition is not purely about platforms.

    Only `defined(X)` terms over known platform macros, combined with && || !
    and parentheses, are decided. Anything else returns None and the branch is
    kept, because guessing would be worse than a false negative.
    """
    expression = condition.strip()
    names = re.findall(r'defined\s*\(?\s*([A-Za-z_]\w*)\s*\)?', expression)
    if not names or any(name not in PLATFORM for name in names):
        return None
    pythonic = re.sub(r'defined\s*\(?\s*([A-Za-z_]\w*)\s*\)?',
                      lambda m: str(PLATFORM[m.group(1)]), expression)
    pythonic = pythonic.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        return bool(eval(pythonic, {"__builtins__": {}}, {}))  # noqa: S307 - platform literals only
    except Exception:
        return None


def windows_view(text):
    """The lines a Windows compile would see, with platform conditionals resolved.

    A conditional whose condition is not about platform macros is left in place
    along with its body, so an unrelated `#if` can never make this lie about
    brace balance.
    """
    kept = []
    # (decided, keeping, already_taken) per open conditional.
    stack = []
    for line in text.split("\n"):
        stripped = line.strip()
        directive = re.match(r'#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)', stripped)
        if directive:
            kind, rest = directive.group(1), directive.group(2)
            if kind in ("if", "ifdef", "ifndef"):
                if kind == "ifdef":
                    value = evaluate("defined(%s)" % rest.strip())
                elif kind == "ifndef":
                    value = evaluate("!defined(%s)" % rest.strip())
                else:
                    value = evaluate(rest)
                if value is None:
                    stack.append((False, True, True))
                else:
                    stack.append((True, value, value))
                continue
            if kind == "elif" and stack:
                decided, _, taken = stack[-1]
                if decided:
                    value = evaluate(rest)
                    value = False if value is None else value
                    stack[-1] = (True, value and not taken, taken or value)
                    continue
            elif kind == "else" and stack:
                decided, _, taken = stack[-1]
                if decided:
                    stack[-1] = (True, not taken, True)
                    continue
            elif kind == "endif" and stack:
                decided, _, _ = stack.pop()
                if decided:
                    continue

        if all(keeping for decided, keeping, _ in stack if decided):
            kept.append(line)
    return "\n".join(kept)


def strip_literals(text):
    """Removes comments, strings and character literals.

    Braces inside them are not code, and a suite full of hex captures and SQL
    has plenty of both.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            i = text.find("\n", i)
            if i < 0:
                break
        elif two == "/*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif text[i] in "\"'":
            quote = text[i]
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
            i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def balance(code):
    pairs = {"}": "{", ")": "(", "]": "["}
    stack = []
    for character in code:
        if character in "{([":
            stack.append(character)
        elif character in pairs:
            if not stack or stack.pop() != pairs[character]:
                return character, len(stack)
    return (None, 0) if not stack else (stack[-1], len(stack))


def main():
    findings = []
    for path in sorted(glob.glob("src/**/*.[ch]pp", recursive=True) + glob.glob("test/cpp/*.cpp")):
        text = open(path, encoding="utf-8").read()
        view = windows_view(text)
        code = strip_literals(view)

        unmatched, depth = balance(code)
        if unmatched is not None:
            findings.append("%s: unbalanced '%s' in the Windows view (depth %d) — a guard "
                            "probably excludes an opening or closing token" % (path, unmatched, depth))

        for header in POSIX_HEADERS.findall(view):
            findings.append("%s: POSIX header <%s> is visible to Windows" % (path, header))

        for call in sorted(set(POSIX_CALLS.findall(code))):
            findings.append("%s: POSIX call %s() is visible to Windows" % (path, call))

        for match in re.finditer(r'enum class \w+\s*(?::\s*[\w:]+\s*)?\{([^}]*)\}', code, re.S):
            for name in re.findall(r'\b([A-Za-z_]\w*)\b', match.group(1)):
                if name in WINDOWS_MACROS:
                    findings.append("%s: enumerator %s collides with a Windows macro" % (path, name))

    if findings:
        for finding in findings:
            sys.stderr.write("check_windows_view: %s\n" % finding)
        sys.stderr.write("check_windows_view: %d finding(s)\n" % len(findings))
        return 1
    print("check_windows_view: the Windows view of %d files is balanced and free of POSIX-only code"
          % len(glob.glob("src/**/*.[ch]pp", recursive=True) + glob.glob("test/cpp/*.cpp")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
