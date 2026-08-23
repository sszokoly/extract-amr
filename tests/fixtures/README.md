# Integration fixtures

Run `python tests/fixtures/generate_fixtures.py` to reproduce the checked-in
captures and golden storage streams.

The generator contains complete Ethernet frames and expected RFC 4867 storage
bytes as literal hexadecimal vectors. It does not import `extract_amr`, use the
draft parser, or derive expected output with production serialization code.
All addresses are reserved RFC 5737 documentation addresses, and all codec
payload bytes are fabricated test patterns rather than recorded audio.
