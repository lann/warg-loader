# Warg Loader

A minimal Warg Package Registry interface for read-only consumers.

## CLI

`warg-loader` is intended to be used primarily as a library, but it also
provides a simple CLI interface:

```console
$ warg-loader localhost:5000 test:pkg
Package: test:pkg
Versions:
  1.0.0
$ warg-loader localhost:5000 fetch 1.0.0
Fetching release details for test:pkg@1.0.0...
Downloading content to "test-pkg-1.0.0.wasm"...
```

## Running Tests

The e2e tests require:
- The [`oras`](https://github.com/oras-project/oras) CLI tool to be available in
  your local `PATH`
- An [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec)-compliant
  registry to be running at `localhost:5000`. An ephemeral registry can be run with:

  ```console
  $ docker run --rm -p 5000:5000 distribution/distribution:edge
  ```

The e2e tests themselves are in the separate [`tests/e2e`](./tests/e2e/) crate:

```console
$ cd tests/e2e
$ cargo run
```

## Publishing to OCI

Until publisher tooling is developed, the [`oras`](https://github.com/oras-project/oras)
CLI tool can be used to publish packages:

> Note: The details of this process (like MIME type) are still being worked on.

```console
$ oras push \
    "${OCI_REGISTRY}/${WARG_NAMESPACE}/${PACKAGE_MAME}:${SEMVER}" \
    "${WASM_FILE}:application/vnd.wasm.content.layer.v1+wasm"

# e.g. to push `component.wasm` as "my-namespace:my-pkg@1.0.0" to `localhost:5000`:
$ oras push \
    localhost:5000/my-namespace/my-pkg:1.0.0 \
    component.wasm:application/vnd.wasm.content.layer.v1+wasm
```

> Note: Some registry implementations may require `--image-spec v1.0` for
> compatibility with this example.