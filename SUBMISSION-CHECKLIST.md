# Submission checklist

Repository URL: **https://github.com/rtl0019/RyansTeam-FALL2026-SQA**

Due: **December 1, 2026, 11:59 PM CST**. Submit the URL on Canvas under **Semester Long Project**.

| Assignment item | Evidence |
| --- | --- |
| Unpack supplied project | Source files and LOCAL-SETUP.md |
| Public repository with team naming pattern | RyansTeam-FALL2026-SQA |
| README with team name and member email | README.md |
| Automatically fuzz ten Python methods | fuzz.py, FUZZING.md, evidence/fuzz-baseline/ |
| Modify ten methods for forensics | parser.py, forensic_logging.py, FORENSICS.md |
| Execute fuzzing in GitHub Actions | .github/workflows/fuzz.yml |
| CI tests and forensic evidence | Workflow, TEST_FORENSICS.py, forensics_demo.py |
| Activities and lessons report | SQA-REPO.md |
| Code, logs, and execution screenshots | evidence/; see SQA-REPO.md for links |

Before submitting:

- Confirm Ryan Lunsford / rtl0019@auburn.edu is registered in the course team spreadsheet.
- Review SQA-REPO.md and ensure the lessons reflect your understanding; add any personal reflection you want to include.
- Check any lecture-specific expectations for the forensics activity against the implemented execution logging.
- Open the latest Actions run and confirm it is successful. Fuzz discoveries are documented upstream bugs; green discovery mode does not mean zero bugs.
- Submit the repository URL on Canvas and check for the submission confirmation.

The repository cannot establish spreadsheet registration or Canvas submission. These must be confirmed in the course systems.
