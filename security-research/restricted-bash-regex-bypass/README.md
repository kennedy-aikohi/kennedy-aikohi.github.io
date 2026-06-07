# Restricted Bash Regex Bypass - Educational PoC

## Overview

This repository contains a Python proof-of-concept that demonstrates how a restricted Bash input filter can be bypassed in a controlled lab environment.

The project is intended for educational security research, defensive learning, and authorized testing only. It is designed to help analysts, students, and developers understand how strict input filters can still be abused when shell expansion behavior is not fully accounted for.

## Purpose

This proof-of-concept demonstrates how Bash parsing behavior can be used to reconstruct command execution using only a limited set of allowed characters.

The goal is to support secure coding awareness and defensive analysis by showing why input validation alone is not always enough when user-controlled data reaches a shell execution context.

## Technique Summary

The script demonstrates the following concepts:

* Restricted character-set analysis
* Bash arithmetic expansion behavior
* Bash parameter expansion behavior
* Indirect expansion logic
* Environment and positional variable manipulation
* Controlled shell-spawning behavior in a lab environment

## Example Filter

The scenario assumes a restricted shell where user input is filtered by a strict regular expression similar to:

```regex
^[${}![:space:]:_=()]+$
```

Even with this restrictive character set, Bash expansion behavior can still introduce unexpected execution paths if the filtered input is later evaluated by a shell.

## Repository Contents

```text
restricted-bash-regex-bypass/
├── README.md
└── restricted_bash_regex_bypass_poc.py
```

## Usage

Edit the target values inside the script before running it:

```python
HOST = ""
PORT = 0
```

Example:

```python
HOST = "127.0.0.1"
PORT = 8080
```

Run the script:

```bash
python restricted_bash_regex_bypass_poc.py
```

If the target service is vulnerable and the lab conditions match the expected restricted-shell behavior, the script attempts to complete the bypass and enter an interactive shell loop.

## Safety Notice

This code is provided for educational and authorized testing only.

Do not use this script against systems you do not own or do not have explicit permission to test. Unauthorized testing may be illegal and unethical.

The author is not responsible for misuse of this material.

## Defensive Lessons

This proof-of-concept highlights several defensive lessons:

* Avoid passing user-controlled input to shell interpreters.
* Do not rely only on regex filtering for shell safety.
* Prefer safe APIs over shell execution.
* Treat shell expansion features as dangerous in restricted environments.
* Log and alert on unexpected shell-spawning behavior.
* Validate security assumptions with adversarial testing in a controlled lab.

## Author

Kennedy Aikohi
