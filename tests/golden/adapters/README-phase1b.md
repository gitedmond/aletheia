# Phase 1B adapter evidence

F16 author-delegated proposal. Expected address/label rows and unmapped counts were
specified from raw pinned-tool output, independently of the adapter implementation.
The four tables cover public dev programs b64 and hashkit-sha, each in hardened and
hardoff variants. Targets and private truth were not used to filter raw matches.

capa names are verbatim from capa-rules 9.4.0, pinned archive commit
2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80. Public native MD5 and SHA1 calibration
fixtures additionally produced `hash data with MD5` and `hash data using SHA1`.
The two Base64 decoding rule names come from the same archive; the WinAPI rule
has basic-block scope and remains counted as unsupported scope. No decode rule
matched the public b64 implementation; coverage is reported without guessing.

FindCrypt 3.1.10 produced CRYPT_SHA256_K on both hashkit-sha variants and CRYPT_MD5
on the public MD5 calibration fixture. The public SHA1 fixture produced no labels;
no SHA1 constant label is invented. Overlapping CRYPT_SHACAL2_K, CRYPT_MD4 and
BLAKE2 labels remain unmapped. A constant match is a tool claim, not ground truth.
Original Phase 1A golden files are preserved.
