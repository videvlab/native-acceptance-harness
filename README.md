# Native acceptance harness

Generic verification harness for Windows x64 and macOS Apple Silicon/Intel standard runners. This repository contains no product source, presets, model files, user data, credentials, or private build provenance.

Reviewed inputs stay in a private release and are retrieved through short-lived URLs held in protected Environment secrets. Exact SHA, byte counts, signature-key hash and engine digest are pinned outside the input bundle. Only the protected main commit can run.

Product process output is captured privately. Public artifacts contain a fixed neutral status and results sealed to the pinned RSA public recipient; the decryption key stays outside CI. The owned hosted runner and reviewed child code remain trusted boundaries.

The workflow requires repository and per-platform Environment configuration. Its presence is not evidence that native acceptance has completed.
