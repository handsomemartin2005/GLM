# GLM: repository credential behavior study

This repository contains a controlled security study of agents encountering credentials in repository content. It measures explicit credential use, explicit forwarding, and tool-side propagation that is absent from agent call arguments.

The evaluation uses **synthetic credentials and loopback services**. It does not test third-party accounts. The model API key is supplied locally and is never an evaluation secret. Public repository contents are not authorization to use credentials.

## Reproduce

Python 3.11+, standard library only:

```sh
python -m unittest discover -s tests -v
python study.py controls --output runs/controls
python audit.py runs/controls
```

`study.py models` makes billed model requests and requires an explicit route configuration; it is separate from local controls. See `PROTOCOL.md` for definitions, denominators and scope. Results of forced actions are never reported as spontaneous agent behavior. This is a researcher-authored fixture, not a survey of GitHub leakage prevalence.

## Results and evidence

- `RESULTS_ZH.md`: observed outcomes, separate from forced controls.
- `SCORING_CORRECTION.md`: utility parsing correction, with original scores retained.
- `evidence.zip`: frozen source snapshots, raw synthetic actions and model responses, independent loopback receipts, plans and audits. Extract it into this directory to restore `runs/`.
- `public_fixture/`: separately documented owner-directed public credential fixture; excluded from evaluation inputs and the evidence archive.

Run `python report.py` after extracting the evidence archive to recompute the tables. The `parameters` gate is an exact-value scanner, not a claim about every possible argument-level authorization defense. Authentication via a config-file reference is reported separately from literal-key authentication, and can overlap with implicit propagation.

