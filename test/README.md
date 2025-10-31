This is a small test suite checking that `publish_cve_advisories` generates the
correct JSON to be sent to CVE services.

The test cases are stored in `.yml` files, and the JSON expected to be generated
is stored in the corresponding `.expected.json` files. To add new testcases,
just expand a existing `.yml` file or create a new one. If an unexpected result
is encountered, it will be written to a new `.actual.json` file that is not
tracked by Git.

Tests run via GitHub actions. To test locally, run:

```
pip install .
test_cve_generation
```
