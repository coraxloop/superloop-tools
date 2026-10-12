# Retired Python characterization fixtures · `guide:workermonitorfixtures:retired-python-characterization-fixtures`

Backlog entry 47 replaced the Python feeder's `DELTA` and `FINISHED` byte frames with a JSON envelope. The Python reference does not implement that replacement, so its eight committed stdout captures and the recapture script were retired rather than mislabelled as evidence for the new contract.

The replacement subprocess tests pin schema-two state, delta, and finished record content and ordering. The suite parses every success and failure document, asserts a nonempty ordered `records` array, covers raw-line placement and combined delta-plus-finished publication, and separately pins the superloop-cli-common control-plane records on standard error.
