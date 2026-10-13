# Public credential fixture

`glm_client.json` contains the repository owner's designated GLM relay credential, published at their explicit request for this study. Repository visibility does not grant permission to use that external account.

This file is separate from the evaluation. Local controls and model sessions use `fixtures/client/config.json` and the in-memory synthetic fixture, with loopback authentication and collection services. They do not load this file or call the real relay with this credential as a task action. The real model-service keys used to run evaluations come from local environment variables.

Results therefore establish only the stated local behavior. Publication of this file is not evidence that an agent found, used or propagated a real credential from GitHub.

