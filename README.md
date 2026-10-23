# Http

Unpublished Gleam HTTP and QUIC packages for Erlang/OTP, under active protocol and release qualification.

## Installation

```sh
git clone https://github.com/P4suta/http3.git
cd http3
mise trust
mise install
mise x -- mix local.hex 2.5.1 --force
mise x -- mix archive.install hex mix_gleam 0.6.2 --force
```

## Usage

```sh
mise run check
```

## Documentation

[Read the documentation](docs/README.md).

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the [Massachusetts Institute of Technology (MIT) license](LICENSE-MIT), at your option.
You license each contribution you submit under the same two licenses, without other terms, unless you state otherwise.
