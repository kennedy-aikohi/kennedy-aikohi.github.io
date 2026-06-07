\# Restricted Bash Regex Bypass - Educational PoC



This repository contains a Python proof-of-concept demonstrating how a restricted Bash input filter can be bypassed in a controlled lab environment.



The script is intended for educational security research, defensive learning, and authorized testing only.



\## Overview



The PoC targets a restricted shell scenario where user input is filtered by a strict regular expression. It demonstrates how Bash parameter expansion and arithmetic expansion can be used to reconstruct command execution using only allowed characters.



\## Technique



The proof-of-concept demonstrates:



\- Restricted character-set analysis

\- Bash arithmetic expansion behavior

\- Parameter expansion abuse

\- Environment and positional variable manipulation

\- Controlled shell-spawning logic in a lab environment



\## Usage



Edit the target values inside the script:



```python

HOST = ""

PORT = 0

Then run:

python restricted_bash_regex_bypass_poc.py
Safety Notice

This code is provided for educational and authorized testing only. Do not use it against systems you do not own or do not have explicit permission to test.

Author

Kennedy Aikohi


Save and close Notepad.

## 5. Check the files

```powershell
dir .\security-research\restricted-bash-regex-bypass

You should see:

README.md
restricted_bash_regex_bypass_poc.py
