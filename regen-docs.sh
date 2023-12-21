#!/usr/bin/env bash

rm -rf target/doc
cargo +nightly doc --no-deps -Zrustdoc-map
rm -rf docs
mv target/doc docs
