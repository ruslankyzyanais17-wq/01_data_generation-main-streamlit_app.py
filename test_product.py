{
  "status": "blocked_before_browser_page_creation",
  "application": "Privacy Threat Dataset v2",
  "environment": "Own cloud environment only",
  "browser": "Installed Chromium /usr/bin/chromium, driven by Playwright",
  "requested_viewports": [
    {
      "width": 1440,
      "height": 1000
    },
    {
      "width": 390,
      "height": 844
    }
  ],
  "streamlit": "Started at 127.0.0.1:8579, usage stats disabled, terminated in finally",
  "blocker": "Chromium aborted before page creation: process_singleton_posix.cc:297 Check failed: . socket() failed: Operation not permitted (1). Also logged chrome_crashpad_handler: --database is required.",
  "browser_tests_executed": [],
  "screenshots_created": [],
  "not_verified": [
    "desktop/mobile visual layout",
    "navigation and sidebar in browser",
    "catalog select/pagination/unique-text/filter/reset interactions",
    "browser downloads and artifact counts"
  ],
  "application_files_modified": false,
  "all_preexisting_noncache_input_hashes_unchanged_during_attempt": true,
  "canonical_input_hashes": {
    "privacy_threat_dataset.jsonl": {
      "expected_sha256": "b7b3ba360ee348d373f54a9ec324346de4b5e3d70c5e1d6f22d23eb8d7754e97",
      "actual_sha256": "b7b3ba360ee348d373f54a9ec324346de4b5e3d70c5e1d6f22d23eb8d7754e97",
      "unchanged": true
    },
    "privacy_threat_dataset.csv": {
      "expected_sha256": "e88589d0668c0e04afa509b1940a605419bfd66a46d4d2c39bce2d7523d09f10",
      "actual_sha256": "e88589d0668c0e04afa509b1940a605419bfd66a46d4d2c39bce2d7523d09f10",
      "unchanged": true
    },
    "privacy_threat_dataset_excel.csv": {
      "expected_sha256": "fbc21cc838b11c0cb9f7bf8c79b7b53789cd49703d84963e64912b85b2937cda",
      "actual_sha256": "fbc21cc838b11c0cb9f7bf8c79b7b53789cd49703d84963e64912b85b2937cda",
      "unchanged": true
    },
    "dataset_source.json": {
      "expected_sha256": "e49521a585124d27f85d062fd4b21959f6a5609b6203ddbec8db29dbb08a63e6",
      "actual_sha256": "e49521a585124d27f85d062fd4b21959f6a5609b6203ddbec8db29dbb08a63e6",
      "unchanged": true
    }
  },
  "scope_constraints": "No original_snapshot code executed; no user computer, external uploads, or website publishing; no access bypass attempted.",
  "note": "Real browser QA did not execute. The optional local attempt harness and machine-specific logs are not part of the release archive. AppTest results are reported separately."
}
