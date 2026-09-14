#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(MANIFEST, "qualification.json").
-define(GENERATED_STATUS, "docs/CONFORMANCE.md").
-define(REQUIREMENTS_MANIFEST, "standards/requirements.json").
-define(RFC_CATALOG, "standards/rfc-catalog.json").
-define(COVERAGE_POLICY, "coverage-policy.json").
-define(COVERAGE_EVIDENCE, "coverage-evidence.json").

main([]) ->
    audit();
main(["check"]) ->
    audit();
main(["render"]) ->
    io:put_chars(render(read_manifest()));
main(["update"]) ->
    Manifest = read_manifest(),
    ok = file:write_file(?GENERATED_STATUS, render(Manifest)),
    io:format("updated ~s from ~s~n", [?GENERATED_STATUS, ?MANIFEST]);
main(_) ->
    erlang:error(status_audit_usage).

audit() ->
    Manifest = read_manifest(),
    assert_equal(schema, 1, maps:get(<<"schema">>, Manifest)),
    assert_equal(
        qualification_date,
        <<"2026-08-30">>,
        maps:get(<<"qualification_date">>, Manifest)
    ),
    Packages = maps:get(<<"packages">>, Manifest),
    audit_test_discovery_contract(),
    audit_coverage_rendering_contract(),
    assert_unique(package_names, [maps:get(<<"name">>, P) || P <- Packages]),
    lists:foreach(fun audit_package/1, Packages),
    audit_boundary(maps:get(<<"boundary">>, Manifest)),
    audit_ffi_inventory(maps:get(<<"ffi_inventory">>, Manifest)),
    HostileMatrix = maps:get(<<"hostile_matrix">>, Manifest),
    audit_hostile_matrix(HostileMatrix),
    audit_stability_matrix(
        maps:get(<<"stability_matrix">>, Manifest),
        maps:get(<<"packages">>, HostileMatrix)
    ),
    audit_gates(maps:get(<<"gates">>, Manifest)),
    Requirements = maps:get(<<"requirements">>, Manifest),
    audit_requirements(Requirements),
    audit_dynamic_requirement_evidence(Requirements),
    audit_findings(maps:get(<<"findings">>, Manifest),
                   maps:get(<<"gates">>, Manifest)),
    Expected = render(Manifest),
    assert_no_unexpanded_tokens(Expected),
    assert_equal(generated_conformance, Expected, read(?GENERATED_STATUS)),
    assert_no_handwritten_live_counts(),
    io:format("qualification manifest and generated status ok~n").

read_manifest() ->
    json:decode(read(?MANIFEST)).

audit_package(Package) ->
    Name = maps:get(<<"name">>, Package),
    ManifestPath = binary_to_list(maps:get(<<"manifest">>, Package)),
    TestPath = binary_to_list(maps:get(<<"tests">>, Package)),
    Toml = read(ManifestPath),
    assert_equal({package_name, ManifestPath}, Name, toml_string(<<"name">>, Toml)),
    assert_equal(
        {package_version, ManifestPath},
        <<"0.1.0">>,
        toml_string(<<"version">>, Toml)
    ),
    Count = count_tests(TestPath),
    case Count > 0 of
        true -> ok;
        false -> erlang:error({no_tests_discovered, TestPath})
    end.

audit_boundary(Boundary) ->
    Path = binary_to_list(maps:get(<<"allowlist">>, Boundary)),
    Baseline = maps:get(<<"baseline_entries">>, Boundary),
    Target = maps:get(<<"target_entries">>, Boundary),
    Status = maps:get(<<"status">>, Boundary),
    Current = allowlist_count(Path),
    case Current =< Baseline of
        true -> ok;
        false -> erlang:error({boundary_allowlist_grew, Baseline, Current})
    end,
    case {Status, Current} of
        {<<"Ready">>, Target} -> ok;
        {<<"Ready">>, _} ->
            erlang:error({boundary_marked_ready_before_target, Target, Current});
        {<<"Blocked">>, Count} when Count > Target -> ok;
        _ -> erlang:error({invalid_boundary_status, Status, Target, Current})
    end.

audit_ffi_inventory(Inventory) ->
    assert_equal(
        ffi_inventory_schema,
        1,
        maps:get(<<"schema">>, Inventory)
    ),
    Sources = maps:get(<<"sources">>, Inventory),
    case Sources of
        [] -> erlang:error(empty_ffi_inventory);
        _ -> ok
    end,
    assert_equal(ffi_inventory_order, lists:usort(Sources), Sources),
    lists:foreach(fun audit_ffi_source/1, Sources),
    Discovered = lists:sort(lists:append([
        discover_ffi_sources("src"),
        discover_ffi_sources("packages/http3/src"),
        discover_ffi_sources("packages/quic_core/src")
    ])),
    assert_equal(ffi_inventory_discovery, Discovered, Sources).

audit_ffi_source(Source) when is_binary(Source) ->
    Path = binary_to_list(Source),
    Allowed = lists:any(
        fun(Prefix) -> lists:prefix(Prefix, Path) end,
        ["src/", "packages/http3/src/", "packages/quic_core/src/"]
    ),
    case Allowed
        andalso lists:suffix("_ffi.erl", Path)
        andalso filelib:is_regular(Path)
    of
        true -> ok;
        false -> erlang:error({invalid_ffi_inventory_source, Source})
    end;
audit_ffi_source(Source) ->
    erlang:error({invalid_ffi_inventory_source, Source}).

discover_ffi_sources(Directory) ->
    filelib:fold_files(
        Directory,
        ".*_ffi\\.erl$",
        true,
        fun(Path, Sources) -> [list_to_binary(Path) | Sources] end,
        []
    ).

audit_hostile_matrix(Matrix) ->
    assert_equal(hostile_matrix_schema, 1, maps:get(<<"schema">>, Matrix)),
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    case is_integer(TailLimit) andalso TailLimit >= 1024
         andalso TailLimit =< 65536 of
        true -> ok;
        false -> erlang:error({invalid_hostile_output_tail_bytes, TailLimit})
    end,
    Families = maps:get(<<"families">>, Matrix),
    case Families of
        [] -> erlang:error(empty_hostile_families);
        _ -> ok
    end,
    assert_unique(hostile_families, Families),
    Packages = maps:get(<<"packages">>, Matrix),
    case Packages of
        [] -> erlang:error(empty_hostile_packages);
        _ -> ok
    end,
    assert_unique(
        hostile_packages,
        [maps:get(<<"name">>, Package) || Package <- Packages]
    ),
    lists:foreach(fun audit_hostile_package/1, Packages),
    case hostile_test_count(Matrix) > 0 of
        true -> ok;
        false -> erlang:error(empty_hostile_matrix)
    end.

audit_hostile_package(Package) ->
    Name = maps:get(<<"name">>, Package),
    lists:foreach(
        fun(Key) ->
            Value = maps:get(Key, Package),
            case is_binary(Value) andalso byte_size(Value) > 0 of
                true -> ok;
                false -> erlang:error({invalid_hostile_package_field, Name, Key})
            end
        end,
        [<<"directory">>, <<"ebin">>, <<"tests">>]
    ),
    Modules = maps:get(<<"modules">>, Package),
    case Modules of
        [] -> erlang:error({empty_hostile_modules, Name});
        _ -> ok
    end,
    assert_unique({hostile_modules, Name}, Modules),
    lists:foreach(
        fun(Module) ->
            Path = hostile_module_path(Package, Module),
            case filelib:is_regular(Path) of
                true -> ok;
                false ->
                    erlang:error(
                        {missing_hostile_test_source, Name, Module, Path}
                    )
            end,
            case count_tests_in_file(Path) > 0 of
                true -> ok;
                false -> erlang:error({empty_hostile_test_module, Name, Module})
            end
        end,
        Modules
    ).

audit_stability_matrix(Matrix, Packages) ->
    assert_equal(stability_matrix_schema, 1, maps:get(<<"schema">>, Matrix)),
    TailLimit = maps:get(<<"output_tail_bytes">>, Matrix),
    case is_integer(TailLimit) andalso TailLimit >= 1024
         andalso TailLimit =< 65536 of
        true -> ok;
        false -> erlang:error({invalid_stability_output_tail_bytes, TailLimit})
    end,
    Targets = maps:get(<<"targets">>, Matrix),
    case Targets of
        [] -> erlang:error(empty_stability_targets);
        _ -> ok
    end,
    assert_unique(
        stability_target_names,
        [maps:get(<<"name">>, Target) || Target <- Targets]
    ),
    lists:foreach(
        fun(Target) -> audit_stability_target(Target, Packages) end,
        Targets
    ).

audit_stability_target(Target, Packages) ->
    Name = stability_binary(Target, <<"name">>),
    PackageName = stability_binary(Target, <<"package">>),
    Module = stability_binary(Target, <<"module">>),
    Test = stability_binary(Target, <<"test">>),
    Repetitions = maps:get(<<"repetitions">>, Target),
    assert_pattern(
        {invalid_stability_target_name, Name},
        Name,
        <<"^[a-z][a-z0-9-]*$">>
    ),
    assert_pattern(
        {invalid_stability_module, Name, Module},
        Module,
        <<"^[a-z][a-z0-9_@]*_test$">>
    ),
    assert_pattern(
        {invalid_stability_test, Name, Test},
        Test,
        <<"^[a-z][a-z0-9_]*_test$">>
    ),
    case is_integer(Repetitions) andalso Repetitions >= 1
         andalso Repetitions =< 1000 of
        true -> ok;
        false -> erlang:error({invalid_stability_repetitions, Name, Repetitions})
    end,
    Package = find_hostile_package(PackageName, Packages),
    Path = hostile_module_path(Package, Module),
    case filelib:is_regular(Path) of
        true -> ok;
        false -> erlang:error({missing_stability_test_source, Name, Path})
    end,
    Pattern = <<"(?m)^pub fn ", Test/binary, "\\s*\\(\\s*\\)">>,
    case re:run(read(Path), Pattern, [{capture, none}]) of
        match -> ok;
        nomatch -> erlang:error({missing_stability_test_function, Name, Path, Test})
    end.

stability_binary(Map, Key) ->
    Value = maps:get(Key, Map),
    case is_binary(Value) andalso byte_size(Value) > 0 of
        true -> Value;
        false -> erlang:error({invalid_stability_field, Key, Value})
    end.

assert_pattern(Label, Value, Pattern) ->
    case re:run(Value, Pattern, [{capture, none}]) of
        match -> ok;
        nomatch -> erlang:error(Label)
    end.

find_hostile_package(Name, [Package | Rest]) ->
    case maps:get(<<"name">>, Package) of
        Name -> Package;
        _ -> find_hostile_package(Name, Rest)
    end;
find_hostile_package(Name, []) ->
    erlang:error({unknown_stability_package, Name}).

audit_gates(Gates) ->
    Names = [maps:get(<<"name">>, Gate) || Gate <- Gates],
    assert_unique(gate_names, Names),
    Missing = lists:sort([
        maps:get(<<"name">>, Gate)
     || Gate <- Gates,
        maps:get(<<"implementation">>, Gate) =:= <<"Missing">>
    ]),
    lists:foreach(
        fun(Gate) ->
            Status = maps:get(<<"status">>, Gate),
            Implementation = maps:get(<<"implementation">>, Gate),
            case {Implementation, Status} of
                {<<"Missing">>, <<"Blocked">>} -> ok;
                {<<"Implemented">>, <<"Blocked">>} -> ok;
                {<<"Implemented">>, <<"Ready">>} -> ok;
                {<<"Implemented">>, <<"ExternalPending">>} -> ok;
                _ -> erlang:error({invalid_gate_state, Gate})
            end
        end,
        Gates
    ),
    ActualMissing = lists:sort(stub_tasks(read(".mise.toml"))),
    assert_equal(unimplemented_gate_tasks, Missing, ActualMissing).

audit_requirements(Requirements) ->
    Ids = [maps:get(<<"id">>, Requirement) || Requirement <- Requirements],
    assert_unique(requirement_ids, Ids),
    lists:foreach(
        fun(Requirement) ->
            assert_status(
                {requirement, maps:get(<<"id">>, Requirement)},
                maps:get(<<"status">>, Requirement),
                [<<"Ready">>, <<"Blocked">>, <<"ExternalPending">>]
            )
        end,
        Requirements
    ).

audit_dynamic_requirement_evidence(Requirements) ->
    assert_evidence_tokens(
        <<"PROD-009">>,
        Requirements,
        [
            <<"{{mapped_standards}}">>,
            <<"{{mapped_pinned_specifications}}">>,
            <<"{{incomplete_standards}}">>,
            <<"{{incomplete_pinned_specifications}}">>
        ]
    ),
    assert_evidence_tokens(
        <<"PROD-011">>,
        Requirements,
        [
            <<"{{standards}}">>, <<"{{pinned_specifications}}">>,
            <<"{{mapped_standards}}">>,
            <<"{{mapped_pinned_specifications}}">>,
            <<"{{requirements}}">>, <<"{{errata_reviewed}}">>,
            <<"{{rfc_catalog_sha256}}">>,
            <<"{{requirement_breakdown}}">>,
            <<"{{inventory_complete}}">>,
            <<"{{incomplete_standards}}">>,
            <<"{{incomplete_pinned_specifications}}">>
        ]
    ),
    assert_evidence_tokens(
        <<"PROD-012">>,
        Requirements,
        [
            <<"{{hostile_tests}}">>, <<"{{hostile_families}}">>,
            <<"{{stability_targets}}">>, <<"{{stability_executions}}">>,
            <<"{{coverage_summary}}">>
        ]
    ).

assert_evidence_tokens(Id, Requirements, Tokens) ->
    Requirement = find_requirement(Id, Requirements),
    Evidence = maps:get(<<"evidence">>, Requirement),
    lists:foreach(
        fun(Token) ->
            case binary:match(Evidence, Token) of
                nomatch ->
                    erlang:error({missing_dynamic_evidence_token, Id, Token});
                _ -> ok
            end
        end,
        Tokens
    ).

find_requirement(Id, [Requirement | Rest]) ->
    case maps:get(<<"id">>, Requirement) of
        Id -> Requirement;
        _ -> find_requirement(Id, Rest)
    end;
find_requirement(Id, []) ->
    erlang:error({missing_product_requirement, Id}).

audit_findings(Findings, Gates) ->
    Ids = [maps:get(<<"id">>, Finding) || Finding <- Findings],
    assert_unique(finding_ids, Ids),
    assert_equal(
        finding_ids,
        [
            <<"PRE-001">>, <<"PRE-002">>, <<"PRE-003">>, <<"PRE-004">>,
            <<"PRE-005">>, <<"PRE-006">>, <<"PRE-007">>, <<"PRE-008">>,
            <<"PRE-009">>, <<"PRE-010">>, <<"PRE-011">>, <<"PRE-012">>
        ],
        lists:sort(Ids)
    ),
    lists:foreach(
        fun(Finding) ->
            lists:foreach(
                fun(Key) ->
                    Value = maps:get(Key, Finding),
                    case is_binary(Value) andalso byte_size(Value) > 0 of
                        true -> ok;
                        false -> erlang:error(
                            {invalid_finding_field,
                             maps:get(<<"id">>, Finding), Key, Value}
                        )
                    end
                end,
                [<<"area">>, <<"evidence">>, <<"closure">>]
            ),
            assert_status(
                {finding, maps:get(<<"id">>, Finding)},
                maps:get(<<"status">>, Finding),
                [<<"Open">>, <<"Closed">>, <<"ExternalPending">>]
            )
        end,
        Findings
    ),
    audit_finding_gates(Findings, Gates).

audit_finding_gates(Findings, Gates) ->
    Mappings = [
        {<<"PRE-005">>, <<"credential-matrix">>},
        {<<"PRE-007">>, <<"qlog-validate">>},
        {<<"PRE-008">>, <<"model">>},
        {<<"PRE-009">>, <<"source-candidate">>},
        {<<"PRE-011">>, <<"release-candidate">>}
    ],
    lists:foreach(fun({FindingId, GateName}) ->
        Finding = find_finding(FindingId, Findings),
        assert_equal({finding_governing_gate, FindingId}, GateName,
                     maps:get(<<"governing_gate">>, Finding)),
        Gate = find_gate(GateName, Gates),
        FindingStatus = maps:get(<<"status">>, Finding),
        GateStatus = maps:get(<<"status">>, Gate),
        Consistent = case GateStatus of
            <<"Ready">> -> FindingStatus =:= <<"Closed">>;
            <<"Blocked">> -> FindingStatus =:= <<"Open">>;
            <<"ExternalPending">> ->
                lists:member(FindingStatus,
                             [<<"Open">>, <<"ExternalPending">>])
        end,
        case Consistent of
            true -> ok;
            false -> erlang:error(
                {finding_gate_status_mismatch, FindingId, FindingStatus,
                 GateName, GateStatus}
            )
        end
    end, Mappings).

find_finding(Id, [Finding | Rest]) ->
    case maps:get(<<"id">>, Finding) of
        Id -> Finding;
        _ -> find_finding(Id, Rest)
    end;
find_finding(Id, []) -> erlang:error({missing_finding, Id}).

find_gate(Name, [Gate | Rest]) ->
    case maps:get(<<"name">>, Gate) of
        Name -> Gate;
        _ -> find_gate(Name, Rest)
    end;
find_gate(Name, []) -> erlang:error({missing_finding_gate, Name}).

render(Manifest) ->
    Packages = maps:get(<<"packages">>, Manifest),
    Boundary = maps:get(<<"boundary">>, Manifest),
    Requirements = maps:get(<<"requirements">>, Manifest),
    Gates = maps:get(<<"gates">>, Manifest),
    Findings = maps:get(<<"findings">>, Manifest),
    Counts = maps:from_list([
        {maps:get(<<"name">>, Package),
         count_tests(binary_to_list(maps:get(<<"tests">>, Package)))}
     || Package <- Packages
    ]),
    BoundaryCount = allowlist_count(
        binary_to_list(maps:get(<<"allowlist">>, Boundary))
    ),
    BaseContext = maps:merge(
        maps:merge(
            Counts#{<<"boundary">> => BoundaryCount},
            requirements_context()
        ),
        hostile_context(maps:get(<<"hostile_matrix">>, Manifest))
    ),
    Context = maps:merge(
        BaseContext,
        stability_context(maps:get(<<"stability_matrix">>, Manifest))
    ),
    iolist_to_binary([
        <<"# Product conformance status\n\n">>,
        <<"<!-- Generated by scripts/status_audit.escript from qualification.json. -->\n">>,
        <<"<!-- Run `mise run status-update`; do not edit this file by hand. -->\n\n">>,
        <<"This matrix is the repository-wide source of truth for the unpublished\n">>,
        <<"`http`, `http3`, and `quic_core` packages. `Ready` means the executable\n">>,
        <<"gate exists and currently passes. `Blocked` means implementation or\n">>,
        <<"release evidence is incomplete. `ExternalPending` is reserved for a\n">>,
        <<"condition that cannot be produced by this unpublished worktree.\n\n">>,
        <<"## Product requirements\n\n">>,
        <<"| ID | Area | Status | Current evidence or required next gate |\n">>,
        <<"| --- | --- | --- | --- |\n">>,
        [requirement_row(Requirement, Context) || Requirement <- Requirements],
        <<"\n## Measured baselines\n\n">>,
        <<"| Package | Version | Discovered tests |\n">>,
        <<"| --- | --- | ---: |\n">>,
        [package_row(Package, Counts) || Package <- Packages],
        <<"\nThe private-boundary allowlist currently has ">>,
        integer_to_binary(BoundaryCount),
        <<" entries; its release target is ">>,
        integer_to_binary(maps:get(<<"target_entries">>, Boundary)),
        <<". The Phase 0 shrink-only baseline is ">>,
        integer_to_binary(maps:get(<<"baseline_entries">>, Boundary)),
        <<".\n\n">>,
        <<"## Executable qualification gates\n\n">>,
        <<"| Gate | Implementation | Status | Purpose |\n">>,
        <<"| --- | --- | --- | --- |\n">>,
        [gate_row(Gate) || Gate <- Gates],
        <<"\n## Pre-publication findings\n\n">>,
        <<"| Finding | Area | Status | Current evidence and closure condition |\n">>,
        <<"| --- | --- | --- | --- |\n">>,
        [finding_row(Finding) || Finding <- Findings],
        <<"\nEvery transition to `Ready` requires a retained Red failure, the bounded\n">>,
        <<"implementation, and Green execution of the affected package plus every\n">>,
        <<"upstream package. Package versions remain `0.1.0`. Tagging, publishing,\n">>,
        <<"pushing, signing commits, and independent audit are not performed here.\n">>
    ]).

requirement_row(Requirement, Context) ->
    row([
        maps:get(<<"id">>, Requirement),
        maps:get(<<"area">>, Requirement),
        code(maps:get(<<"status">>, Requirement)),
        expand(maps:get(<<"evidence">>, Requirement), Context)
    ]).

package_row(Package, Counts) ->
    Name = maps:get(<<"name">>, Package),
    row([Name, <<"0.1.0">>, integer_to_binary(maps:get(Name, Counts))]).

gate_row(Gate) ->
    row([
        code(maps:get(<<"name">>, Gate)),
        maps:get(<<"implementation">>, Gate),
        code(maps:get(<<"status">>, Gate)),
        maps:get(<<"purpose">>, Gate)
    ]).

finding_row(Finding) ->
    row([
        code(maps:get(<<"id">>, Finding)),
        maps:get(<<"area">>, Finding),
        code(maps:get(<<"status">>, Finding)),
        iolist_to_binary([
            maps:get(<<"evidence">>, Finding),
            <<" Closure: ">>,
            maps:get(<<"closure">>, Finding)
        ])
    ]).

row(Cells) ->
    [<<"| ">>, lists:join(<<" | ">>, [escape_cell(Cell) || Cell <- Cells]), <<" |\n">>].

code(Value) ->
    <<"`", Value/binary, "`">>.

escape_cell(Value) when is_binary(Value) ->
    NoPipes = binary:replace(Value, <<"|">>, <<"\\|">>, [global]),
    binary:replace(NoPipes, <<"\n">>, <<" ">>, [global]).

expand(Value, Context) ->
    maps:fold(
        fun(Key, ContextValue, Acc) ->
            Token = <<"{{", Key/binary, "}}">>,
            binary:replace(
                Acc,
                Token,
                context_value(ContextValue),
                [global]
            )
        end,
        Value,
        Context
    ).

context_value(Value) when is_integer(Value) -> integer_to_binary(Value);
context_value(Value) when is_binary(Value) -> Value.

requirements_context() ->
    Manifest = json:decode(read(?REQUIREMENTS_MANIFEST)),
    Standards = maps:get(<<"standards">>, Manifest),
    Pinned = maps:get(<<"pinned_specifications">>, Manifest),
    Completed = [
        Standard
     || Standard <- Standards,
        maps:get(<<"map_complete">>, Standard) =:= true
    ],
    CompletedPinned = [
        Specification
     || Specification <- Pinned,
        maps:get(<<"map_complete">>, Specification) =:= true
    ],
    AllDocuments = Standards ++ Pinned,
    CompletedDocuments = Completed ++ CompletedPinned,
    Catalog = json:decode(read(?RFC_CATALOG)),
    CatalogSource = maps:get(<<"source">>, Catalog),
    RequirementsContext = #{
        <<"standards">> => length(Standards),
        <<"pinned_specifications">> => length(Pinned),
        <<"mapped_standards">> => length(Completed),
        <<"mapped_pinned_specifications">> => length(CompletedPinned),
        <<"incomplete_standards">> => length(Standards) - length(Completed),
        <<"incomplete_pinned_specifications">> =>
            length(Pinned) - length(CompletedPinned),
        <<"requirements">> => lists:sum([
            standard_requirement_count(Document) || Document <- AllDocuments
        ]),
        <<"errata_reviewed">> => lists:sum([
            standard_errata_count(Standard) || Standard <- Standards
        ]),
        <<"rfc_catalog_sha256">> => maps:get(<<"sha256">>, CatalogSource),
        <<"requirement_breakdown">> =>
            requirement_breakdown(CompletedDocuments),
        <<"inventory_complete">> => bool_binary(
            maps:get(<<"inventory_complete">>, Manifest)
        )
    },
    maps:merge(RequirementsContext, coverage_context()).

coverage_context() ->
    Policy = coverage_policy(),
    SourcePaths = coverage_source_paths(Policy),
    CurrentSource = coverage_digest(SourcePaths),
    Summary = case filelib:is_regular(?COVERAGE_EVIDENCE) of
        false ->
            <<"No source-bound current coverage evidence is retained; the ",
              "95/90 full and 100/100 changed thresholds therefore remain ",
              "unproven.">>;
        true ->
            Evidence = json:decode(read(?COVERAGE_EVIDENCE)),
            case maps:get(<<"source_sha256">>, Evidence, <<>>) =:= CurrentSource
                 andalso maps:get(<<"policy_sha256">>, Evidence, <<>>) =:=
                     coverage_file_digest(?COVERAGE_POLICY) of
                false ->
                    <<"The retained coverage evidence does not match the ",
                      "current coverage source/policy digest; the 95/90 full ",
                      "and 100/100 changed thresholds therefore remain ",
                      "unproven.">>;
                true -> current_coverage_summary(
                    Evidence, Policy, length(SourcePaths)
                )
            end
    end,
    #{<<"coverage_summary">> => Summary}.

coverage_policy() ->
    Policy = json:decode(read(?COVERAGE_POLICY)),
    audit_coverage_policy_document(Policy),
    Policy.

audit_coverage_policy_document(Policy) ->
    assert_equal(coverage_policy_schema, 2, maps:get(<<"schema">>, Policy)),
    audit_coverage_coordinate_methodology(
        coverage_policy_coordinate_methodology,
        maps:get(<<"coordinate_methodology">>, Policy)
    ),
    Capture = maps:get(<<"capture">>, Policy),
    Minimum = maps:get(<<"minimum_repetitions">>, Capture),
    Maximum = maps:get(<<"maximum_repetitions">>, Capture),
    Quiescent = maps:get(<<"required_quiescent_repetitions">>, Capture),
    case is_integer(Minimum) andalso is_integer(Maximum) andalso
         is_integer(Quiescent) andalso Minimum >= 2 andalso
         Minimum =< Maximum andalso Maximum =< 100 andalso
         Quiescent >= 1 andalso Quiescent =< Minimum of
        true -> ok;
        false -> erlang:error(
            {invalid_coverage_capture_policy, Minimum, Maximum, Quiescent}
        )
    end,
    Thresholds = maps:get(<<"thresholds_basis_points">>, Policy),
    lists:foreach(fun(Mode) ->
        Metrics = maps:get(Mode, Thresholds),
        lists:foreach(fun(Metric) ->
            Value = maps:get(Metric, Metrics),
            case is_integer(Value) andalso Value >= 0 andalso Value =< 10000 of
                true -> ok;
                false -> erlang:error(
                    {invalid_coverage_threshold, Mode, Metric, Value}
                )
            end
        end, [<<"lines">>, <<"branches">>])
    end, [<<"changed">>, <<"full">>]),
    lists:foreach(fun(Key) ->
        Values = maps:get(Key, Policy),
        case Values =/= [] andalso
             length(Values) =:= length(lists:usort(Values)) of
            true -> ok;
            false -> erlang:error({invalid_coverage_source_policy, Key})
        end,
        lists:foreach(fun coverage_policy_path/1, Values)
    end, [<<"source_files">>, <<"source_trees">>]),
    ok.

audit_coverage_coordinate_methodology(Label, Methodology) ->
    assert_equal(Label, expected_coverage_coordinate_methodology(), Methodology).

expected_coverage_coordinate_methodology() ->
    #{<<"schema">> => 1,
      <<"metric_coordinates">> => <<"generated_erlang_physical_lines">>,
      <<"line_universe">> => <<"otp_cover_executable_lines">>,
      <<"clause_alternative_universe">> =>
          <<"beam_debug_abstract_multi_clause_alternatives">>,
      <<"clause_alternative_coverage">> =>
          <<"any_sibling_exclusive_otp_cover_artifact_line">>,
      <<"gleam_source_attribution">> =>
          <<"glance_name_arity_function_span_including_attached_attributes">>,
      <<"erlang_source_attribution">> =>
          <<"byte_identical_source_artifact_lines">>,
      <<"changed_selection">> =>
          <<"source_span_overlap_with_whole_module_fallback">>,
      <<"generated_clause_exclusion">> => <<"none">>,
      <<"unclaimed_control_flow">> =>
          <<"short_circuit_guard_timeout_and_exception_outcomes">>}.

coverage_source_paths(Policy) ->
    Files = [coverage_policy_path(Path)
             || Path <- maps:get(<<"source_files">>, Policy)],
    Trees = [coverage_policy_path(Path)
             || Path <- maps:get(<<"source_trees">>, Policy)],
    lists:foreach(fun(Tree) ->
        case filelib:is_dir(Tree) of
            true -> ok;
            false -> erlang:error({missing_coverage_source_tree, Tree})
        end
    end, Trees),
    TreePaths = lists:append([
        filelib:fold_files(Tree, ".*", true,
                           fun(Path, Acc) -> [Path | Acc] end, [])
        || Tree <- Trees
    ]),
    Paths = lists:usort(Files ++ TreePaths),
    lists:foreach(fun(Path) ->
        case filelib:is_regular(Path) of
            true -> ok;
            false -> erlang:error({missing_coverage_source, Path})
        end
    end, Paths),
    Paths.

coverage_policy_path(Value) when is_binary(Value), byte_size(Value) > 0 ->
    Path = binary_to_list(Value),
    Parts = filename:split(Path),
    case filename:pathtype(Path) =:= relative andalso
         not lists:member("..", Parts) of
        true -> Path;
        false -> erlang:error({unsafe_coverage_policy_path, Value})
    end;
coverage_policy_path(Value) ->
    erlang:error({invalid_coverage_policy_path, Value}).

coverage_digest(Paths) ->
    Material = [[unicode:characters_to_binary(coverage_relative(Path)),
                 0, read(Path), 0]
                || Path <- lists:sort(Paths)],
    coverage_hex(crypto:hash(sha256, Material)).

coverage_relative(Path) ->
    RootParts = filename:split(filename:absname(".")),
    PathParts = filename:split(filename:absname(Path)),
    case coverage_drop_prefix(RootParts, PathParts) of
        [] -> ".";
        Parts -> filename:join(Parts)
    end.

coverage_drop_prefix([Part | Root], [Part | Path]) ->
    coverage_drop_prefix(Root, Path);
coverage_drop_prefix([], Path) -> Path;
coverage_drop_prefix(_, Path) -> Path.

coverage_file_digest(Path) -> coverage_hex(crypto:hash(sha256, read(Path))).

coverage_hex(Bytes) -> binary:encode_hex(Bytes, lowercase).

current_coverage_summary(Evidence, Policy, SourceFiles) ->
    assert_equal(coverage_evidence_schema, 2,
                 maps:get(<<"schema">>, Evidence)),
    Methodology = maps:get(<<"coordinate_methodology">>, Policy),
    audit_coverage_coordinate_methodology(
        coverage_policy_coordinate_methodology, Methodology
    ),
    assert_equal(
        coverage_evidence_coordinate_methodology,
        Methodology,
        maps:get(<<"coordinate_methodology">>, Evidence)
    ),
    assert_equal(coverage_evidence_source_files, SourceFiles,
                 maps:get(<<"source_files">>, Evidence)),
    Thresholds = maps:get(<<"thresholds_basis_points">>, Policy),
    assert_equal(coverage_evidence_thresholds, Thresholds,
                 maps:get(<<"thresholds_basis_points">>, Evidence)),
    CapturePolicy = maps:get(<<"capture">>, Policy),
    assert_equal(coverage_evidence_capture_policy, CapturePolicy,
                 maps:get(<<"capture_policy">>, Evidence)),
    Full = audit_coverage_metric_set(
        <<"full">>, maps:get(<<"full">>, Evidence),
        maps:get(<<"full">>, Thresholds)
    ),
    Changed = audit_coverage_metric_set(
        <<"changed">>, maps:get(<<"changed">>, Evidence),
        maps:get(<<"changed">>, Thresholds)
    ),
    Statuses = maps:get(<<"statuses">>, Evidence),
    assert_equal(coverage_full_status, maps:get(status, Full),
                 maps:get(<<"full">>, Statuses)),
    assert_equal(coverage_changed_status, maps:get(status, Changed),
                 maps:get(<<"changed">>, Statuses)),
    RepetitionCounts = audit_coverage_captures(
        Evidence, CapturePolicy
    ),
    FullMetrics = maps:get(metrics, Full),
    ChangedMetrics = maps:get(metrics, Changed),
    FullLines = maps:get(<<"basis_points">>, maps:get(<<"lines">>, FullMetrics)),
    FullBranches = maps:get(
        <<"basis_points">>, maps:get(<<"branches">>, FullMetrics)
    ),
    ChangedLines = maps:get(
        <<"basis_points">>, maps:get(<<"lines">>, ChangedMetrics)
    ),
    ChangedBranches = maps:get(
        <<"basis_points">>, maps:get(<<"branches">>, ChangedMetrics)
    ),
    iolist_to_binary([
        <<"The current source-bound adaptive OTP cover capture used ">>,
        coverage_repetition_text(RepetitionCounts),
        <<" same-VM suite repetitions and reached the policy-required ">>,
        integer_to_binary(maps:get(
            <<"required_quiescent_repetitions">>, CapturePolicy
        )),
        <<"-repetition quiescent tail with converged process, port, ETS, ",
          "and mailbox counts for every package. It reports full generated-",
          "artifact line/observable compiled clause-alternative coverage of ">>,
        coverage_percentage(FullLines), <<"/">>,
        coverage_percentage(FullBranches),
        <<" and changed coverage on the same metrics of ">>,
        coverage_percentage(ChangedLines), <<"/">>,
        coverage_percentage(ChangedBranches), <<"; the full and changed ",
          "gates are ">>, maps:get(status, Full), <<" and ">>,
        maps:get(status, Changed),
        <<" against the manifest-owned 95/90 and 100/100 thresholds. Gleam ",
          "source attribution uses attribute-inclusive Glance function spans; ",
          "unattributed changed lines conservatively select the whole module.">>
    ]).

audit_coverage_metric_set(Label, Metrics, Thresholds) ->
    Lines = audit_coverage_metric(Label, <<"lines">>,
                                  maps:get(<<"lines">>, Metrics)),
    Branches = audit_coverage_metric(Label, <<"branches">>,
                                     maps:get(<<"branches">>, Metrics)),
    Status = case maps:get(<<"total">>, Lines) > 0 andalso
                  maps:get(<<"total">>, Branches) > 0 andalso
                  maps:get(<<"basis_points">>, Lines) >=
                      maps:get(<<"lines">>, Thresholds) andalso
                  maps:get(<<"basis_points">>, Branches) >=
                      maps:get(<<"branches">>, Thresholds) of
        true -> <<"Ready">>;
        false -> <<"Blocked">>
    end,
    #{status => Status, metrics => Metrics}.

audit_coverage_metric(Set, Metric, Value) ->
    Covered = maps:get(<<"covered">>, Value),
    Total = maps:get(<<"total">>, Value),
    BasisPoints = maps:get(<<"basis_points">>, Value),
    Expected = case Total of 0 -> 0; _ -> Covered * 10000 div Total end,
    case is_integer(Covered) andalso is_integer(Total) andalso
         Covered >= 0 andalso Total >= Covered andalso
         BasisPoints =:= Expected of
        true -> Value;
        false -> erlang:error(
            {invalid_coverage_metric, Set, Metric, Covered, Total, BasisPoints}
        )
    end.

audit_coverage_captures(Evidence, CapturePolicy) ->
    Counts = maps:get(<<"capture_repetitions">>, Evidence),
    Captures = maps:get(<<"captures">>, Evidence),
    ExpectedPackages = [<<"http">>, <<"http3">>, <<"quic_core">>],
    CountPackages = lists:sort([
        maps:get(<<"package">>, Count) || Count <- Counts
    ]),
    CapturePackages = lists:sort([
        maps:get(<<"package">>, Capture) || Capture <- Captures
    ]),
    assert_equal(coverage_count_packages, ExpectedPackages, CountPackages),
    assert_equal(coverage_capture_packages, ExpectedPackages, CapturePackages),
    Minimum = maps:get(<<"minimum_repetitions">>, CapturePolicy),
    Maximum = maps:get(<<"maximum_repetitions">>, CapturePolicy),
    RequiredQuiescent = maps:get(
        <<"required_quiescent_repetitions">>, CapturePolicy
    ),
    CountMap = maps:from_list([
        {maps:get(<<"package">>, Count), maps:get(<<"repetitions">>, Count)}
        || Count <- Counts
    ]),
    lists:foreach(fun(Capture) ->
        Package = maps:get(<<"package">>, Capture),
        Repetitions = maps:get(<<"repetition_count">>, Capture),
        assert_equal({coverage_capture_count, Package},
                     maps:get(Package, CountMap), Repetitions),
        case Repetitions >= Minimum andalso Repetitions =< Maximum of
            true -> ok;
            false -> erlang:error(
                {invalid_coverage_repetitions, Package, Repetitions}
            )
        end,
        assert_equal({coverage_paths_saturated, Package}, true,
                     maps:get(<<"paths_saturated">>, Capture)),
        Growth = maps:get(<<"growth">>, Capture),
        assert_equal({coverage_growth_saturated, Package}, true,
                     maps:get(<<"paths_saturated">>, Growth)),
        assert_equal({coverage_growth_repetitions, Package}, Repetitions,
                     maps:get(<<"repetitions">>, Growth)),
        assert_equal({coverage_final_repetition_grew, Package}, false,
                     maps:get(<<"final_repetition_grew">>, Growth)),
        QuiescentTail = maps:get(<<"quiescent_tail_repetitions">>, Growth),
        case valid_coverage_quiescent_tail(
            RequiredQuiescent, QuiescentTail, Repetitions
        ) of
            true -> ok;
            false -> erlang:error(
                {invalid_coverage_quiescent_tail, Package,
                 RequiredQuiescent, QuiescentTail, Repetitions}
            )
        end,
        Runtime = maps:get(<<"runtime_convergence">>, Capture),
        assert_equal({coverage_runtime_converged, Package}, true,
                     maps:get(<<"final_resource_counts_converged">>, Runtime))
    end, Captures),
    CountMap.

coverage_repetition_text(Counts) ->
    Entries = [
        <<Package/binary, " ", (integer_to_binary(maps:get(Package, Counts)))/binary>>
        || Package <- [<<"http">>, <<"http3">>, <<"quic_core">>]
    ],
    iolist_to_binary(lists:join(<<", ">>, Entries)).

coverage_percentage(BasisPoints) ->
    iolist_to_binary(io_lib:format("~B.~2.10.0B%",
                                  [BasisPoints div 100,
                                   BasisPoints rem 100])).

standard_requirement_count(Standard) ->
    length(maps:get(<<"requirements">>, Standard, [])).

standard_errata_count(Standard) ->
    case maps:find(<<"errata">>, Standard) of
        {ok, Errata} ->
            case maps:get(<<"inventory_complete">>, Errata, false) of
                true -> length(maps:get(<<"entries">>, Errata, []));
                false -> 0
            end;
        error -> 0
    end.

requirement_breakdown([]) ->
    <<"No requirement maps are complete.">>;
requirement_breakdown(Standards) ->
    Entries = [
        iolist_to_binary([
            maps:get(<<"id">>, Standard),
            <<" has ">>,
            integer_to_binary(standard_requirement_count(Standard)),
            <<"/">>,
            integer_to_binary(standard_errata_count(Standard))
        ])
     || Standard <- Standards
    ],
    iolist_to_binary([lists:join(<<", ">>, Entries), <<".">>]).

bool_binary(true) -> <<"true">>;
bool_binary(false) -> <<"false">>.

hostile_context(Matrix) ->
    #{
        <<"hostile_tests">> => hostile_test_count(Matrix),
        <<"hostile_families">> => length(maps:get(<<"families">>, Matrix))
    }.

stability_context(Matrix) ->
    Targets = maps:get(<<"targets">>, Matrix),
    #{
        <<"stability_targets">> => length(Targets),
        <<"stability_executions">> => lists:sum([
            maps:get(<<"repetitions">>, Target) || Target <- Targets
        ])
    }.

hostile_test_count(Matrix) ->
    lists:sum([
        count_tests_in_file(hostile_module_path(Package, Module))
     || Package <- maps:get(<<"packages">>, Matrix),
        Module <- maps:get(<<"modules">>, Package)
    ]).

hostile_module_path(Package, Module) ->
    Tests = binary_to_list(maps:get(<<"tests">>, Package)),
    Relative = binary:replace(Module, <<"@">>, <<"/">>, [global]),
    filename:join(Tests, binary_to_list(Relative) ++ ".gleam").

count_tests(Path) ->
    Files = filelib:fold_files(
        Path,
        ".*\\.(gleam|erl)$",
        true,
        fun(File, Acc) -> [File | Acc] end,
        []
    ),
    lists:sum([count_tests_in_file(File) || File <- Files]).

count_tests_in_file(Path) ->
    case filename:extension(Path) of
        ".gleam" -> count_gleam_tests(read(Path));
        ".erl" -> count_erlang_tests(Path)
    end.

count_gleam_tests(Contents) ->
    Pattern = <<"(?m)^pub fn [A-Za-z0-9_]+_test_?\\s*\\(">>,
    case re:run(Contents, Pattern, [global]) of
        {match, Matches} -> length(Matches);
        nomatch -> 0
    end.

count_erlang_tests(Path) ->
    case epp:parse_file(Path, [], []) of
        {ok, Forms} -> count_erlang_test_exports(Forms);
        {error, Reason} ->
            erlang:error({erlang_test_source_parse_failed, Path, Reason})
    end.

count_erlang_test_exports(Forms) ->
    Exports = lists:usort(lists:append([
        Entries
     || {attribute, _Line, export, Entries} <- Forms
    ])),
    length([
        Name
     || {Name, 0} <- Exports,
        is_eunit_test_name(Name)
    ]).

is_eunit_test_name(Name) ->
    Text = atom_to_list(Name),
    lists:suffix("_test", Text) orelse lists:suffix("_test_", Text).

audit_test_discovery_contract() ->
    Gleam = <<"pub fn visible_test() { Nil }\n"
              "fn private_test() { Nil }\n"
              "pub fn generated_test_() { Nil }\n">>,
    assert_equal(test_discovery_gleam, 2, count_gleam_tests(Gleam)),
    ErlangForms = [
        {attribute, 1, export, [
            {self_test, 0},
            {generated_test_, 0},
            {wrong_arity_test, 1},
            {ordinary, 0}
        ]}
    ],
    assert_equal(
        test_discovery_erlang,
        2,
        count_erlang_test_exports(ErlangForms)
    ).

audit_coverage_rendering_contract() ->
    CapturePolicy = #{
        <<"minimum_repetitions">> => 10,
        <<"maximum_repetitions">> => 30,
        <<"required_quiescent_repetitions">> => 3
    },
    Methodology = expected_coverage_coordinate_methodology(),
    Thresholds = #{
        <<"changed">> => #{<<"lines">> => 10000, <<"branches">> => 10000},
        <<"full">> => #{<<"lines">> => 9500, <<"branches">> => 9000}
    },
    Policy = #{
        <<"schema">> => 2,
        <<"coordinate_methodology">> => Methodology,
        <<"capture">> => CapturePolicy,
        <<"thresholds_basis_points">> => Thresholds,
        <<"source_files">> => [<<"coverage-policy.json">>],
        <<"source_trees">> => [<<"src">>]
    },
    ok = audit_coverage_policy_document(Policy),
    Evidence = #{
        <<"schema">> => 2,
        <<"coordinate_methodology">> => Methodology,
        <<"source_files">> => 1,
        <<"thresholds_basis_points">> => Thresholds,
        <<"capture_policy">> => CapturePolicy,
        <<"full">> => coverage_rendering_metric_set(95, 100, 90, 100),
        <<"changed">> => coverage_rendering_metric_set(100, 100, 100, 100),
        <<"statuses">> => #{
            <<"full">> => <<"Ready">>,
            <<"changed">> => <<"Ready">>
        },
        <<"capture_repetitions">> => [
            #{<<"package">> => Package, <<"repetitions">> => 10}
         || Package <- [<<"http">>, <<"http3">>, <<"quic_core">>]
        ],
        <<"captures">> => [
            coverage_rendering_capture(Package)
         || Package <- [<<"http">>, <<"http3">>, <<"quic_core">>]
        ]
    },
    Summary = current_coverage_summary(Evidence, Policy, 1),
    assert_equal(
        coverage_policy_schema_rejects_v1,
        {mismatch, coverage_policy_schema},
        caught_status_audit_mismatch(fun() ->
            audit_coverage_policy_document(Policy#{<<"schema">> => 1})
        end)
    ),
    WrongMethodology = Methodology#{
        <<"metric_coordinates">> => <<"gleam_logical_lines">>
    },
    assert_equal(
        coverage_policy_rejects_unknown_coordinate_methodology,
        {mismatch, coverage_policy_coordinate_methodology},
        caught_status_audit_mismatch(fun() ->
            audit_coverage_policy_document(
                Policy#{<<"coordinate_methodology">> => WrongMethodology}
            )
        end)
    ),
    assert_equal(
        coverage_evidence_schema_rejects_v1,
        {mismatch, coverage_evidence_schema},
        caught_status_audit_mismatch(fun() ->
            current_coverage_summary(Evidence#{<<"schema">> => 1}, Policy, 1)
        end)
    ),
    assert_equal(
        coverage_evidence_rejects_coordinate_methodology_mismatch,
        {mismatch, coverage_evidence_coordinate_methodology},
        caught_status_audit_mismatch(fun() ->
            current_coverage_summary(
                Evidence#{<<"coordinate_methodology">> => WrongMethodology},
                Policy,
                1
            )
        end)
    ),
    assert_equal(
        coverage_summary_uses_policy_quiescent_tail,
        true,
        nomatch =/= binary:match(
            Summary, <<"policy-required 3-repetition quiescent tail">>
        )
    ),
    assert_equal(coverage_quiescent_tail_accepts_policy, true,
                 valid_coverage_quiescent_tail(3, 3, 10)),
    assert_equal(coverage_quiescent_tail_rejects_short_tail, false,
                 valid_coverage_quiescent_tail(3, 2, 10)),
    assert_equal(coverage_quiescent_tail_rejects_overlong_tail, false,
                 valid_coverage_quiescent_tail(3, 11, 10)),
    assert_equal(coverage_quiescent_tail_rejects_non_integer, false,
                 valid_coverage_quiescent_tail(3, <<"3">>, 10)).

valid_coverage_quiescent_tail(Required, Actual, Repetitions) ->
    is_integer(Actual) andalso Actual >= Required andalso
        Actual =< Repetitions.

caught_status_audit_mismatch(Function) ->
    try Function() of
        _ -> unexpected_success
    catch
        error:{status_audit_mismatch, Label, _Expected, _Actual} ->
            {mismatch, Label};
        error:Reason ->
            {unexpected_error, Reason}
    end.

coverage_rendering_metric_set(LineCovered, LineTotal, BranchCovered, BranchTotal) ->
    #{
        <<"lines">> => coverage_rendering_metric(LineCovered, LineTotal),
        <<"branches">> => coverage_rendering_metric(BranchCovered, BranchTotal)
    }.

coverage_rendering_metric(Covered, Total) ->
    #{
        <<"covered">> => Covered,
        <<"total">> => Total,
        <<"basis_points">> => Covered * 10000 div Total
    }.

coverage_rendering_capture(Package) ->
    #{
        <<"package">> => Package,
        <<"repetition_count">> => 10,
        <<"paths_saturated">> => true,
        <<"growth">> => #{
            <<"repetitions">> => 10,
            <<"paths_saturated">> => true,
            <<"final_repetition_grew">> => false,
            <<"quiescent_tail_repetitions">> => 3
        },
        <<"runtime_convergence">> => #{
            <<"final_resource_counts_converged">> => true
        }
    }.

allowlist_count(Path) ->
    Lines = binary:split(read(Path), <<"\n">>, [global]),
    length([
        Line
     || Raw <- Lines,
        Line <- [trim(Raw)],
        Line =/= <<>>,
        binary:at(Line, 0) =/= $#
    ]).

stub_tasks(Mise) ->
    Lines = binary:split(Mise, <<"\n">>, [global]),
    {_, Names} = lists:foldl(fun stub_line/2, {undefined, []}, Lines),
    lists:usort(Names).

stub_line(Line, {Current, Names}) ->
    case re:run(Line, <<"^\\[tasks\\.([^]]+)\\]$">>, [{capture, [1], binary}]) of
        {match, [Name]} -> {Name, Names};
        nomatch ->
            case Current =/= undefined andalso
                 binary:match(Line, <<"not implemented yet">>) =/= nomatch of
                true -> {Current, [Current | Names]};
                false -> {Current, Names}
            end
    end.

toml_string(Key, Contents) ->
    Pattern = <<"(?m)^", Key/binary, "\\s*=\\s*\"([^\"]+)\"\\s*$">>,
    case re:run(Contents, Pattern, [{capture, [1], binary}]) of
        {match, [Value]} -> Value;
        nomatch -> erlang:error({missing_toml_string, Key})
    end.

assert_no_handwritten_live_counts() ->
    Checks = [
        {"docs/TESTING.md", <<"currently has 255 tests">>},
        {"docs/TESTING.md", <<"currently has 322 tests">>},
        {"docs/TESTING.md", <<"currently has 299 tests">>},
        {"packages/http3/docs/TESTING.md", <<"Ten Phase 5 gates">>},
        {"packages/http3/docs/CONFORMANCE.md", <<"allowlist now has 41 entries">>},
        {"packages/http3/docs/CONFORMANCE.md", <<"suite passes 322 tests">>}
    ],
    lists:foreach(
        fun({Path, Pattern}) ->
            case binary:match(read(Path), Pattern) of
                nomatch -> ok;
                _ -> erlang:error({handwritten_live_status, Path, Pattern})
            end
        end,
        Checks
    ),
    case re:run(
        read(?MANIFEST),
        <<"[0-9]+-test(?:, [0-9]+-family)? hostile matrix">>,
        [{capture, none}]
    ) of
        nomatch -> ok;
        match -> erlang:error(handwritten_hostile_matrix_count)
    end.

assert_no_unexpanded_tokens(Rendered) ->
    case binary:match(Rendered, <<"{{">>) of
        nomatch -> ok;
        {Offset, _Length} ->
            erlang:error({unexpanded_status_token, Offset})
    end.

assert_status(_Label, Status, Allowed) when is_binary(Status) ->
    case lists:member(Status, Allowed) of
        true -> ok;
        false -> erlang:error({invalid_status, Status, Allowed})
    end.

assert_unique(Label, Values) ->
    assert_equal(Label, lists:sort(Values), lists:usort(Values)).

assert_equal(_Label, Expected, Expected) -> ok;
assert_equal(Label, Expected, Actual) ->
    erlang:error({status_audit_mismatch, Label, Expected, Actual}).

trim(Value) ->
    string:trim(Value).

read(Path) ->
    case file:read_file(Path) of
        {ok, Contents} -> Contents;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.
