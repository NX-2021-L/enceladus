# How to build Lambda packages for the Linux runtime

This guide builds a Python Lambda deployment package whose compiled dependencies will run on AWS Lambda's Linux runtime. Follow it whenever a function depends on packages with native extensions — `PyJWT`, `cryptography`, `cffi`, and anything else that ships compiled wheels.

> **Do not build deployment packages on macOS.** Compiled dependencies built on macOS produce Mach-O binaries that the Linux runtime cannot load. The failure is *silent*: the import fails at runtime, not at build time, and the symptom is downstream — for example, JWT validation quietly disabling itself and every authenticated request returning 401. For the full incident analysis, see [JWT authentication forensics](../explanation/jwt-authentication-forensics.md).

## Build with platform targeting

Install dependencies into the package directory with explicit Linux platform targeting, so `pip` fetches Linux wheels instead of building for the host:

```bash
pip install \
  --platform manylinux2014_x86_64 \
  --only-binary=:all: \
  -r requirements.txt \
  -t build_dir
```

- `--platform manylinux2014_x86_64` selects Linux x86-64 wheels.
- `--only-binary=:all:` forces wheel use and fails loudly if a source-only package would otherwise be compiled for the host.
- `-t build_dir` installs into the directory you will zip for the function.

## For arm64 functions

If the target function runs on the `arm64` architecture, select the matching wheel platform:

```bash
pip install \
  --platform manylinux2014_aarch64 \
  --only-binary=:all: \
  -r requirements.txt \
  -t build_dir
```

Match the `--platform` to the function's configured architecture; a mismatch reproduces the same silent import failure this guide exists to prevent.

## Verify before shipping

Confirm the package contains Linux shared objects, not Mach-O:

```bash
file build_dir/cryptography/hazmat/bindings/_rust*.so
```

The output should name an ELF object (Linux), not a Mach-O object (macOS). If you see Mach-O, the package was built on the host — rebuild with the platform flags above.

The repository's per-function `deploy.sh` scripts apply this pattern; consult [repository operations](../reference/repository-operations.md) for how functions are deployed.
