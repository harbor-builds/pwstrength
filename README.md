# pwstrength

Most password strength checkers give you a single verdict: "weak", or a
progress bar that goes from red to green. That's fine for a signup form, but
it's useless when you're auditing a batch of passwords, or trying to explain
to someone *why* their twenty-character password still got rejected.

pwstrength reports findings the way a compiler reports syntax errors: file,
line, column, and a caret pointing at the exact characters that are the
problem.

## Install

No dependencies, so there's nothing to resolve. Either drop the `pwstrength/`
package next to your code, or install it locally:

```
pip install -e .
```

## Library usage

```python
from pwstrength import analyze

report = analyze("hunter2222222")

for finding in report.findings:
    print(finding.code, finding.severity, finding.message, finding.start, finding.end)

print(report.score)          # 0-4
print(report.is_acceptable())  # False if any finding is an error
```

## CLI usage

The CLI checks a file of passwords, one per line, and prints a diagnostic
block per problem found, plus a score line per password:

```
$ cat sample-passwords.txt
hunter2222222
Tr0ub4dor&3xyz9Q
qwerty123
$ python -m pwstrength.cli sample-passwords.txt
sample-passwords.txt:1:7: warning [PW003]: 7 repeated '2' characters in a row reduce entropy
  |
1 | hunter2222222
  |       ^^^^^^^
sample-passwords.txt:1: score 2/4 (fair)
sample-passwords.txt:2: score 4/4 (very strong)
sample-passwords.txt:3:1: warning [PW005]: 'qwerty' follows the keyboard layout, easy to guess
  |
3 | qwerty123
  | ^^^^^^
sample-passwords.txt:3: score 1/4 (weak)
```

With no file argument, it reads passwords from stdin:

```
$ echo "password" | python -m pwstrength.cli
<stdin>:1:1: error [PW002]: this is one of the most common passwords in use, it will be guessed instantly
  |
1 | password
  | ^^^^^^^^
<stdin>:1: score 0/4 (very weak)
```

Exit code is `0` if every password was clean, `1` otherwise, so it's usable
as a pre-commit hook for a leaked-secrets file or similar.

## What it checks today

| Code | Meaning |
| ---- | ------- |
| PW001 | password shorter than the minimum length (8) |
| PW002 | password is on the built-in common-password list |
| PW003 | 4+ repeated characters in a row |
| PW004 | 4+ character ascending/descending run (`abcd`, `4321`) |
| PW005 | 4+ character run that follows a keyboard row (`qwer`, `asdf`) |

When two pattern rules flag exactly the same characters (`1234` is both a
sequence and on the keyboard's number row), only one finding is reported,
the sequential one.

`Report.score` is a 0-4 rating derived from length, character variety, and
the findings above.

## Design notes

Every `Finding` carries a `start`/`end` column range into the password
string, not just a message. That's what lets the CLI draw a caret under the
exact characters that triggered the rule, and it's also what a future GUI or
web form could use to underline the bad span inline instead of showing a
generic "try again" banner.
