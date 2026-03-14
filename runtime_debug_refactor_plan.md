# Runtime Debug Refactor Replay Plan

This plan captures how to replay the runtime-state and explicit-runtime debug refactor on a clean `libsrtp-3` checkout.

## Goal

Remove persistent mutable global runtime state and make runtime ownership explicit through SRTP, crypto-kernel, and debug/error reporting paths.

## Commit 1

Commit message:

```text
Refactor runtime-owned SRTP and crypto-kernel state
```

Scope:

- Add `srtp_runtime_t` lifecycle and runtime-scoped APIs in `include/srtp.h`.
- Add runtime ownership/back-pointers in `include/srtp_priv.h`.
- Move crypto-kernel state off globals into runtime in `crypto/kernel/crypto_kernel.c`.
- Update declarations in `crypto/include/crypto_kernel.h`.
- Move error/report handler state off globals into runtime in:
  - `crypto/kernel/err.c`
  - `crypto/include/err.h`
- Update in-repo callers to use runtime-aware session creation and runtime APIs:
  - `crypto/test/kernel_driver.c`
  - `test/srtp_driver.c`
  - `test/rtpw.c`
  - `test/rtp_decoder.c`
  - `test/rtp.c`
  - `test/rtp.h`
  - `fuzzer/fuzzer.c`
- Keep `debug_print*` behavior functional even if some paths still use fallback reporting temporarily.

Verification:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure -R "kernel_driver|test_srtp|srtp_driver"
```

## Commit 2

Commit message:

```text
Pass runtime through OpenSSL debug and self-test paths
```

Scope:

- Remove the ambient runtime bridge entirely from:
  - `crypto/include/err.h`
  - `crypto/kernel/err.c`
- Make cipher/auth alloc and self-test helpers runtime-aware in:
  - `crypto/include/cipher.h`
  - `crypto/include/auth.h`
  - `crypto/cipher/cipher.c`
  - `crypto/hash/auth.c`
- Add/store runtime on active OpenSSL/internal contexts:
  - `crypto/include/aes_icm_ext.h`
  - `crypto/include/aes_gcm.h`
  - `crypto/include/hmac.h`
  - `crypto/include/null_auth.h`
  - `crypto/include/null_cipher.h`
  - `crypto/include/sha1.h`
- Thread explicit runtime through active library code paths:
  - `srtp/srtp.c`
  - `crypto/cipher/aes_icm.c`
  - `crypto/cipher/aes_icm_ossl.c`
  - `crypto/cipher/aes_gcm_ossl.c`
  - `crypto/hash/hmac.c`
  - `crypto/hash/hmac_ossl.c`
  - `crypto/hash/sha1.c`
  - `crypto/hash/null_auth.c`
  - `crypto/cipher/null_cipher.c`
- Remove allocator debug logging in `crypto/kernel/alloc.c` because it has no valid runtime owner.
- Update helper tests in `crypto/test/cipher_driver.c`.

Verification:

```bash
cmake --build build
ctest --test-dir build --output-on-failure -R "kernel_driver|test_srtp|srtp_driver|cipher_driver"
```

## Commit 3

Commit message:

```text
Pass runtime through non-OpenSSL crypto backends
```

Scope:

- Apply the same explicit-runtime pattern to remaining backend files:
  - AES ICM: NSS, wolfSSL, MbedTLS
  - AES GCM: NSS, wolfSSL, MbedTLS
  - HMAC: NSS, wolfSSL, MbedTLS
- Ensure backend-private context structs carry `runtime`.
- Convert backend `alloc` callbacks to take runtime first and store it on the instance.
- Replace remaining library-side `debug_print*` calls that still rely on fallback form.

Verification:

- Build and test with each backend you care about.
- At minimum, verify the active backend end-to-end after each patch round.

## Suggested Workflow

1. Start from a clean branch.
2. Keep the three commit boundaries explicit from the start.
3. Avoid mixing formatting-only edits into these commits.
4. Stage tracked files by commit boundary instead of using `git add .`.
5. Expect `srtp/srtp.c` to span commit 1 and commit 2; if needed, split carefully by hunk.

## Notes

- Scratch buffers are intentionally out of scope.
- Immutable static lookup tables and test vectors are intentionally out of scope.
- The OpenSSL/CMake path is the first fully verified target; alternate backends are follow-up work.
