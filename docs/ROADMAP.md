# Roadmap

The implementation order is:

1. preserve the existing HTTP/3 and QUIC baselines and establish the
   `http` -> `http3` -> `quic_core` package boundary;
2. remove every `http3` dependency on `quic_core/internal/**`;
3. deliver common Body, Error, deadline, resource, and diagnostic contracts;
4. add strict HTTP/1.1 and complete HTTP/2 runtimes;
5. add reusable unified clients, servers, policy features, and extensions;
6. close conformance, coverage, fuzz/model, interoperability, performance,
   reproducibility, provenance, and independent-audit gates.

Every item is completed through a failing test first. Versions remain `0.1.0`,
and release or publication actions are out of scope.
