# Detection benchmark (baseline)

420 examples, 360 labeled entities, 3.94s total.

## Per class (span overlap, type must match)

| class | gold | pred | precision | recall | F1 | recall (any type) |
|---|---:|---:|---:|---:|---:|---:|
| US_SSN | 43 | 28 | 1.00 | 0.65 | 0.79 | 0.81 |
| EMAIL | 47 | 47 | 1.00 | 1.00 | 1.00 | 1.00 |
| PHONE | 36 | 30 | 0.97 | 0.81 | 0.88 | 0.86 |
| CREDIT_CARD | 42 | 34 | 1.00 | 0.81 | 0.89 | 0.90 |
| IBAN | 20 | 20 | 1.00 | 1.00 | 1.00 | 1.00 |
| PERSON | 36 | 77 | 0.44 | 0.94 | 0.60 | 0.94 |
| ADDRESS | 28 | 23 | 0.87 | 0.68 | 0.76 | 0.96 |
| AWS_ACCESS_KEY | 26 | 22 | 1.00 | 0.85 | 0.92 | 0.88 |
| GITHUB_TOKEN | 22 | 17 | 1.00 | 0.77 | 0.87 | 0.86 |
| GENERIC_API_KEY | 20 | 35 | 0.46 | 0.80 | 0.58 | 0.80 |
| JWT | 20 | 0 | - | 0.00 | 0.00 | 0.75 |
| PRIVATE_KEY | 20 | 0 | - | 0.00 | 0.00 | 0.50 |
| **overall, strict** | 360 | 683 | 0.39 | 0.74 | 0.51 | |
| **overall, any type** | 360 | 683 | 0.70 | 0.88 | 0.78 | |

## Detector types outside the benchmark classes

| detector type | predictions | overlapping a real label |
|---|---:|---:|
| DATE_TIME | 190 | 75 |
| MEDICAL_LICENSE | 3 | 2 |
| ORGANIZATION | 77 | 32 |
| URL | 80 | 68 |

## Example level: was anything sensitive detected?

| mode | precision | recall | F1 | false alarm rate on negatives | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| text | 0.84 | 0.91 | 0.87 | 0.48 | 283 | 52 | 29 | 56 |
| payload | 0.84 | 0.91 | 0.87 | 0.52 | 284 | 56 | 28 | 52 |
| correct_span | 0.84 | 0.86 | 0.85 | 0.48 | 269 | 52 | 43 | 56 |

`text` = detect_text on the raw string. `payload` = JSON examples parsed and walked with detect_mapping, like instrument_tool does. `correct_span` = a positive only counts if some detection overlaps a real label.

## Per tag

| tag | examples | flagged | labeled entities hit (any type) |
|---|---:|---:|---:|
| ADDRESS | 20 | 19 | 19/20 |
| AWS_ACCESS_KEY | 20 | 20 | 20/20 |
| CREDIT_CARD | 20 | 20 | 20/20 |
| EMAIL | 20 | 20 | 20/20 |
| GENERIC_API_KEY | 20 | 19 | 16/20 |
| GITHUB_TOKEN | 20 | 18 | 17/20 |
| IBAN | 20 | 20 | 20/20 |
| JWT | 20 | 18 | 15/20 |
| PERSON | 20 | 20 | 20/20 |
| PHONE | 20 | 16 | 15/20 |
| PRIVATE_KEY | 20 | 14 | 10/20 |
| US_SSN | 20 | 18 | 16/20 |
| evasion:fullwidth | 12 | 12 | 12/12 |
| evasion:spaced | 12 | 7 | 7/12 |
| evasion:split_json | 12 | 6 | 6/12 |
| evasion:zero_width | 12 | 12 | 12/12 |
| multi | 24 | 24 | 70/72 |
| neg:b64_blob | 12 | 1 | - |
| neg:git_sha | 12 | 6 | - |
| neg:hex_hash | 12 | 3 | - |
| neg:nine_digits | 12 | 7 | - |
| neg:order_id | 12 | 8 | - |
| neg:timestamp | 12 | 10 | - |
| neg:uuid | 12 | 8 | - |
| neg:version | 12 | 0 | - |
| neg:zip_code | 12 | 9 | - |

## Worst false negatives (up to 3 per class, lowest-recall classes first)

| id | class | tag | format | value | found as |
|---|---|---|---|---|---|
| ex-0201 | JWT | JWT | json | `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTEzNTE5NSIsImlhdCI6MTcwODIxNzY` | GENERIC_API_KEY |
| ex-0202 | JWT | JWT | chat | `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzMjI4MjA1MyIsImlhdCI6MTcwOTI1ODM` | PERSON |
| ex-0203 | JWT | JWT | log | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAzODc3NSIsImlhdCI6MTcwOTU5MDQ` | GENERIC_API_KEY, OTHER:URL |
| ex-0221 | PRIVATE_KEY | PRIVATE_KEY | json | `-----BEGIN OPENSSH PRIVATE KEY-----\nEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPL31` | - |
| ex-0222 | PRIVATE_KEY | PRIVATE_KEY | email | `-----BEGIN RSA PRIVATE KEY-----\nEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAM22` | - |
| ex-0223 | PRIVATE_KEY | PRIVATE_KEY | log | `-----BEGIN RSA PRIVATE KEY-----\nEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAM26` | - |
| ex-0001 | US_SSN | US_SSN | json | `547915995` | - |
| ex-0008 | US_SSN | US_SSN | log | `811309005` | - |
| ex-0010 | US_SSN | US_SSN | code | `772845778` | - |
| ex-0121 | ADDRESS | ADDRESS | json | `6454 Elm Lane, Fairview, TX 17107` | - |
| ex-0122 | ADDRESS | ADDRESS | chat | `690 Riverside Court, Madison, WI 35381` | OTHER:DATE_TIME, OTHER:ORGANIZATION, PERSON |
| ex-0127 | ADDRESS | ADDRESS | chat | `1768 Maple Rd, Fairview, TX 23542` | OTHER:DATE_TIME, OTHER:ORGANIZATION |
| ex-0161 | GITHUB_TOKEN | GITHUB_TOKEN | json | `github_pat_EXAMPLEEXAMPLEEXAMPLE9_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXA9` | GENERIC_API_KEY |
| ex-0162 | GITHUB_TOKEN | GITHUB_TOKEN | chat | `github_pat_EXAMPLEEXAMPLEEXAMPLE7_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAM` | - |
| ex-0165 | GITHUB_TOKEN | GITHUB_TOKEN | code | `github_pat_EXAMPLEEXAMPLEEXAMPL10_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEX10` | GENERIC_API_KEY |
| ex-0184 | GENERIC_API_KEY | GENERIC_API_KEY | email | `sk_live_...(32 chars)` | - |
| ex-0187 | GENERIC_API_KEY | GENERIC_API_KEY | chat | `cdf523d2fc7c2eb7041c77dbef46326f` | - |
| ex-0189 | GENERIC_API_KEY | GENERIC_API_KEY | email | `74wmuasf-psqoq93y-fl4vmunr-7h88ooxb` | - |
| ex-0042 | PHONE | PHONE | chat | `+44 20 7946 0952` | - |
| ex-0044 | PHONE | PHONE | email | `+91 98680 41669` | OTHER:DATE_TIME |
| ex-0046 | PHONE | PHONE | json | `303-736-9454` | - |
| ex-0398 | CREDIT_CARD | evasion:spaced | email | `5 4 2 4 5 1 7 3 2 2 7 2 5 2 1 9` | - |
| ex-0401 | CREDIT_CARD | evasion:spaced | email | `5 1 4 1 0 5 1 2 6 1 1 0 3 1 1 5` | - |
| ex-0404 | CREDIT_CARD | evasion:spaced | email | `5 1 4 6 7 0 0 8 1 9 3 6 7 4 0 9` | OTHER:DATE_TIME |
| ex-0411 | AWS_ACCESS_KEY | evasion:split_json | json | `AKIAELZZRP", "key_suffix": "L27XYZQGUF` | - |
| ex-0414 | AWS_ACCESS_KEY | evasion:split_json | json | `AKIAWZTPF4", "key_suffix": "YERDGIPEUF` | OTHER:ORGANIZATION |
| ex-0417 | AWS_ACCESS_KEY | evasion:split_json | json | `AKIA2U3UOP", "key_suffix": "OATA2QTHPI` | - |
| ex-0244 | PERSON | multi | json | `Noah Cohen` | - |
| ex-0253 | PERSON | multi | json | `Kenji Rossi` | - |

## Worst false positives (up to 5 per detector type, highest score first)

| id | predicted | score | tag | format | matched text |
|---|---|---:|---|---|---|
| ex-0318 | OTHER:MEDICAL_LICENSE | 1.0 | neg:git_sha | json | `ed7276846` |
| ex-0001 | OTHER:DATE_TIME | 0.85 | US_SSN | json | `96930` |
| ex-0006 | OTHER:DATE_TIME | 0.85 | US_SSN | json | `26824` |
| ex-0011 | OTHER:DATE_TIME | 0.85 | US_SSN | json | `42424` |
| ex-0013 | OTHER:DATE_TIME | 0.85 | US_SSN | log | `2026-02` |
| ex-0018 | OTHER:DATE_TIME | 0.85 | US_SSN | log | `1767682992` |
| ex-0002 | OTHER:ORGANIZATION | 0.85 | US_SSN | chat | `SSN` |
| ex-0009 | OTHER:ORGANIZATION | 0.85 | US_SSN | email | `SSN` |
| ex-0018 | OTHER:ORGANIZATION | 0.85 | US_SSN | log | `INFO` |
| ex-0070 | OTHER:ORGANIZATION | 0.85 | CREDIT_CARD | code | `PAN` |
| ex-0084 | OTHER:ORGANIZATION | 0.85 | IBAN | email | `IBAN` |
| ex-0005 | OTHER:URL | 0.85 | US_SSN | code | `requests.ge` |
| ex-0015 | OTHER:URL | 0.85 | US_SSN | code | `requests.ge` |
| ex-0035 | OTHER:URL | 0.85 | EMAIL | code | `requests.ge` |
| ex-0065 | OTHER:URL | 0.85 | CREDIT_CARD | code | `requests.ge` |
| ex-0070 | OTHER:URL | 0.85 | CREDIT_CARD | code | `requests.ge` |
| ex-0118 | PERSON | 0.85 | PERSON | log | `info svc` |
| ex-0148 | PERSON | 0.85 | AWS_ACCESS_KEY | log | `info svc` |
| ex-0169 | PERSON | 0.85 | GITHUB_TOKEN | email | `Push` |
| ex-0202 | PERSON | 0.85 | JWT | chat | `Cookie` |
| ex-0203 | PERSON | 0.85 | JWT | log | `info svc` |
