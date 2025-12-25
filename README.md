## Overview
A Python tool that analyzes common Windows persistence artifacts such as registry autoruns, scheduled tasks, and services to identify suspicious persistence mechanisms using explainable, rule-based logic.

## Artifacts Analyzed
- Registry Run keys
- Scheduled tasks
- Windows services

## Detection Logic
- Flags persistence entries executing from user-writable directories
- Highlights elevated execution contexts (SYSTEM / LocalSystem)
- Focuses on explainable, rule-based analysis

## Usage
```bash
python3 analyzer.py
