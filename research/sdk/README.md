# HyperCat Tool SDK

Build your own tools for HyperCat — in C, C++, Python, or Rust — and HyperCat runs them as confined,
operator-approved subprocesses. This is the SDK only, licensed Apache-2.0. HyperCat itself (the application) is
separate software, published in its own repository
([HyperCat-Agent](https://github.com/savannah-i-g/HyperCat-Agent), also Apache-2.0).

A tool is a small program that speaks a tiny line-framed JSON protocol over a Unix-domain socket: it checks in,
gets confined to a least-privilege kernel sandbox (Landlock + seccomp), and answers tool calls. The SDK does the
protocol and the sandbox for you; you write one function and register it.

## What is inside

```
include/hc_tool.h          the C/C++ header (the public ABI)
lib/libhc_tool_sdk.a       a self-contained static library (links with libc only; cJSON baked in)
python/hypercat_tool.py    the Python helper (pure standard library; no build step)
rust/hypercat-tool/        the Rust crate (links lib/ via the hc_tool_confine FFI)
examples/                  a worked example in each language
docs/AUTHORING.md          what to write
docs/BUILDING.md           how to compile, link, and install your tool
docs/PROTOCOL.md           the wire + manifest contract (write a tool in any language)
LICENSE, NOTICE, THIRD_PARTY.txt
```

## Quick start

- **C / C++:** include `hc_tool.h`, link `lib/libhc_tool_sdk.a`, call `hc_tool_main()`. See
  `examples/hello_tool/` and `docs/BUILDING.md`.
- **Python:** copy `python/hypercat_tool.py` next to your script and call `hypercat_tool.serve({...})`. See
  `examples/wordcount_tool_py/`.
- **Rust:** add the `rust/hypercat-tool` crate, point it at `lib/`, and call `hypercat_tool::serve(&[...])`. See
  `rust/hypercat-tool/examples/reverse.rs`.

## Platform

Linux x86-64, glibc 2.35 or newer (the static lib is built at that floor). Tool confinement is Linux-only;
HyperCat refuses to run a tool it cannot confine.

## Licence

Apache-2.0 (`LICENSE`). The bundled cJSON is MIT, preserved in `NOTICE` / `THIRD_PARTY.txt`.
