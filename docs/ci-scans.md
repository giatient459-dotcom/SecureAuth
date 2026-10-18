# CI Build and Security Scans

## Gradle Build Scan (Develocity)

The workflow is opt-in and does not add the Develocity extension to normal local builds.

1. Read and accept Develocity's Build Scan terms: https://gradle.com/help/legal-terms-of-use
2. In GitHub, open **Settings → Secrets and variables → Actions → Variables**.
3. Add:
   - `DEVELOCITY_SCAN_ENABLED=true`
   - `DEVELOCITY_SCAN_TERMS_ACCEPTED=true` only after the repository owner has accepted the terms.
4. Run the **Maven Build Scan (Develocity)** workflow from **Actions**, or push a commit / open a PR to a watched branch.

The workflow adds the Gradle Build Scan only inside that CI job and runs `gradle build --scan`. The normal Build workflow remains independent. The Build Scan may contain build metadata, dependency coordinates, environment details, and task timings; review Develocity's data collection terms before enabling it.

## OWASP Dependency-Check

1. Request an NVD API key: https://nvd.nist.gov/developers/request-an-api-key
2. In GitHub, open **Settings → Secrets and variables → Actions → Secrets**.
3. Add a repository secret named `NVD_API_KEY` containing the key.
4. Run **OWASP Dependency-Check** from **Actions**, or wait for the scheduled weekly run.

The scan uses OWASP Dependency-Check Gradle plugin `13.0.0`, scans the Gradle multi-project build, creates HTML/JSON reports when analysis runs, and fails the scan job when it finds a vulnerability at or above CVSS 7.0. This security workflow is separate from the standard build, so it cannot break artifact compilation/upload. The first NVD database update may take several minutes.

If `NVD_API_KEY` is absent, the workflow explicitly skips the actual vulnerability analysis and writes a warning to the workflow summary. A green workflow status in that case does **not** mean dependencies were scanned or found clean.
