# Detection benchmark (after_fast_path)

420 examples, 360 labeled entities, 1.86s total.

## Per class (span overlap, type must match)

| class | gold | pred | precision | recall | F1 | recall (any type) |
|---|---:|---:|---:|---:|---:|---:|
| US_SSN | 43 | 35 | 1.00 | 0.81 | 0.90 | 0.81 |
| EMAIL | 47 | 47 | 1.00 | 1.00 | 1.00 | 1.00 |
| PHONE | 36 | 36 | 0.97 | 0.97 | 0.97 | 0.97 |
| CREDIT_CARD | 42 | 38 | 1.00 | 0.90 | 0.95 | 0.90 |
| IBAN | 20 | 20 | 1.00 | 1.00 | 1.00 | 1.00 |
| PERSON | 36 | 45 | 0.76 | 0.94 | 0.84 | 0.94 |
| ADDRESS | 28 | 48 | 0.96 | 1.00 | 0.98 | 1.00 |
| AWS_ACCESS_KEY | 26 | 22 | 1.00 | 0.85 | 0.92 | 0.85 |
| GITHUB_TOKEN | 22 | 22 | 1.00 | 1.00 | 1.00 | 1.00 |
| GENERIC_API_KEY | 20 | 25 | 1.00 | 0.95 | 0.97 | 0.95 |
| JWT | 20 | 20 | 1.00 | 1.00 | 1.00 | 1.00 |
| PRIVATE_KEY | 20 | 20 | 1.00 | 1.00 | 1.00 | 1.00 |
| **overall, strict** | 360 | 378 | 0.96 | 0.94 | 0.95 | |
| **overall, any type** | 360 | 378 | 0.99 | 0.94 | 0.97 | |

## Detector types outside the benchmark classes

| detector type | predictions | overlapping a real label |
|---|---:|---:|

## Example level: was anything sensitive detected?

| mode | precision | recall | F1 | false alarm rate on negatives | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| text | 1.00 | 0.94 | 0.97 | 0.00 | 294 | 0 | 18 | 108 |
| payload | 1.00 | 0.94 | 0.97 | 0.00 | 294 | 0 | 18 | 108 |
| correct_span | 1.00 | 0.94 | 0.97 | 0.00 | 294 | 0 | 18 | 108 |

`text` = detect_text on the raw string. `payload` = JSON examples parsed and walked with detect_mapping, like instrument_tool does. `correct_span` = a positive only counts if some detection overlaps a real label.

## Per tag

| tag | examples | flagged | labeled entities hit (any type) |
|---|---:|---:|---:|
| ADDRESS | 20 | 20 | 20/20 |
| AWS_ACCESS_KEY | 20 | 20 | 20/20 |
| CREDIT_CARD | 20 | 20 | 20/20 |
| EMAIL | 20 | 20 | 20/20 |
| GENERIC_API_KEY | 20 | 19 | 19/20 |
| GITHUB_TOKEN | 20 | 20 | 20/20 |
| IBAN | 20 | 20 | 20/20 |
| JWT | 20 | 20 | 20/20 |
| PERSON | 20 | 20 | 20/20 |
| PHONE | 20 | 19 | 19/20 |
| PRIVATE_KEY | 20 | 20 | 20/20 |
| US_SSN | 20 | 16 | 16/20 |
| evasion:fullwidth | 12 | 12 | 12/12 |
| evasion:spaced | 12 | 12 | 12/12 |
| evasion:split_json | 12 | 0 | 0/12 |
| evasion:zero_width | 12 | 12 | 12/12 |
| multi | 24 | 24 | 70/72 |
| neg:b64_blob | 12 | 0 | - |
| neg:git_sha | 12 | 0 | - |
| neg:hex_hash | 12 | 0 | - |
| neg:nine_digits | 12 | 0 | - |
| neg:order_id | 12 | 0 | - |
| neg:timestamp | 12 | 0 | - |
| neg:uuid | 12 | 0 | - |
| neg:version | 12 | 0 | - |
| neg:zip_code | 12 | 0 | - |

## Worst false negatives (up to 3 per class, lowest-recall classes first)

| id | class | tag | format | value | found as |
|---|---|---|---|---|---|
| ex-0001 | US_SSN | US_SSN | json | `547915995` | - |
| ex-0010 | US_SSN | US_SSN | code | `772845778` | - |
| ex-0014 | US_SSN | US_SSN | email | `259213629` | - |
| ex-0411 | AWS_ACCESS_KEY | evasion:split_json | json | `AKIAELZZRP", "key_suffix": "L27XYZQGUF` | - |
| ex-0414 | AWS_ACCESS_KEY | evasion:split_json | json | `AKIAWZTPF4", "key_suffix": "YERDGIPEUF` | - |
| ex-0417 | AWS_ACCESS_KEY | evasion:split_json | json | `AKIA2U3UOP", "key_suffix": "OATA2QTHPI` | - |
| ex-0410 | CREDIT_CARD | evasion:split_json | json | `4757", "3361", "8319", "5994` | - |
| ex-0413 | CREDIT_CARD | evasion:split_json | json | `4999", "5857", "7064", "6003` | - |
| ex-0416 | CREDIT_CARD | evasion:split_json | json | `4943", "0075", "3705", "5953` | - |
| ex-0244 | PERSON | multi | json | `Noah Cohen` | - |
| ex-0253 | PERSON | multi | json | `Kenji Rossi` | - |
| ex-0187 | GENERIC_API_KEY | GENERIC_API_KEY | chat | `cdf523d2fc7c2eb7041c77dbef46326f` | - |
| ex-0047 | PHONE | PHONE | chat | `(713) 865-7130` | - |

## Worst false positives (up to 5 per detector type, highest score first)

| id | predicted | score | tag | format | matched text |
|---|---|---:|---|---|---|
| ex-0169 | PERSON | 0.85 | GITHUB_TOKEN | email | `Push` |
| ex-0202 | PERSON | 0.85 | JWT | chat | `Cookie` |
| ex-0209 | PERSON | 0.85 | JWT | email | `Cookie` |
| ex-0219 | PERSON | 0.85 | JWT | email | `Cookie` |
