#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(MANIFEST, "standards/requirements.json").
-define(RFC_CATALOG, "standards/rfc-catalog.json").
-define(OUTPUT, "build/requirements/report.json").
-define(BASELINE_DATE, <<"2026-08-30">>).
-define(NORMATIVE_SCOPE,
        <<"Atomic uppercase BCP 14 mandatory and advisory clauses; MAY and "
          "OPTIONAL are excluded.">>).
-define(LEGACY_NORMATIVE_SCOPE,
        <<"Atomic case-insensitive normative must, should, and recommended "
          "clauses in pre-BCP 14 prose; may, optional, and need-not "
          "permissions are excluded.">>).

main([]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "requirements audit failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(["--self-test"]) ->
    try self_test() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "requirements audit self-test failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(_) ->
    io:format(standard_error,
              "usage: requirements_audit.escript [--self-test]~n", []),
    halt(2).

run() ->
    Manifest = decode(?MANIFEST),
    ensure(maps:get(<<"schema">>, Manifest) =:= 4, invalid_schema),
    Baseline = maps:get(<<"baseline_date">>, Manifest),
    ensure(Baseline =:= ?BASELINE_DATE, stale_baseline),
    Policy = audit_policy(maps:get(<<"policy">>, Manifest)),
    Standards = maps:get(<<"standards">>, Manifest),
    ensure(is_list(Standards) andalso Standards =/= [], empty_standard_inventory),
    Ids = [maps:get(<<"id">>, Standard) || Standard <- Standards],
    ensure(length(Ids) =:= length(lists:usort(Ids)), duplicate_standard),
    RfcCatalog = audit_rfc_catalog(decode(?RFC_CATALOG), Standards, Baseline),
    lists:foreach(
        fun(Standard) -> audit_rfc_identity(Standard, RfcCatalog) end,
        Standards
    ),
    Resolve = fun assert_evidence_reference/1,
    StandardReports = [audit_standard(Standard, Policy, Baseline, Resolve)
                       || Standard <- Standards],
    PinnedSpecifications = maps:get(<<"pinned_specifications">>, Manifest),
    ensure(is_list(PinnedSpecifications),
           invalid_pinned_specification_inventory),
    PinnedIds = [maps:get(<<"id">>, Specification)
                 || Specification <- PinnedSpecifications],
    ensure(length(PinnedIds) =:= length(lists:usort(PinnedIds)),
           duplicate_pinned_specification),
    PinnedReports = [audit_pinned_specification(
                         Specification, Policy, Baseline, Resolve)
                     || Specification <- PinnedSpecifications],
    Registries = maps:get(<<"registries">>, Manifest),
    lists:foreach(fun(Registry) -> audit_registry(Registry, Baseline) end,
                  Registries),
    Snapshots = maps:get(<<"non_rfc_snapshots">>, Manifest),
    lists:foreach(fun assert_file/1, Snapshots),
    AllReports = StandardReports ++ PinnedReports,
    IncompleteReports = [Report || Report <- AllReports,
                         maps:get(status, Report) =/= <<"Mapped">>],
    Incomplete = [maps:get(id, Report) || Report <- IncompleteReports],
    BlockerSummary = blocker_summary(IncompleteReports),
    InventoryComplete = maps:get(<<"inventory_complete">>, Manifest),
    ensure(is_boolean(InventoryComplete), invalid_inventory_status),
    Status = case InventoryComplete =:= true andalso Incomplete =:= [] of
                 true -> <<"Ready">>;
                 false -> <<"Blocked">>
             end,
    Counts = report_counts(StandardReports, PinnedReports),
    Report = #{status => Status,
               schema => 4,
               baseline_date => Baseline,
               standards => StandardReports,
               pinned_specifications => PinnedReports,
               counts => Counts,
               inventory_complete => InventoryComplete,
               incomplete_requirement_maps => Incomplete,
               incomplete_blocker_counts => BlockerSummary,
               rfc_catalog => ?RFC_CATALOG,
               registries => length(Registries),
               snapshots => Snapshots},
    ok = write_report(Report),
    case Status of
        <<"Ready">> ->
            io:format("requirement inventory ok (~B RFCs, ~B pinned "
                      "specifications, ~B requirements)~n",
                      [length(Standards), length(PinnedSpecifications),
                       maps:get(requirements, Counts)]),
            ok;
        <<"Blocked">> ->
            io:format(standard_error,
                      "requirements inventory remains Blocked: ~B/~B RFC "
                      "and ~B/~B pinned maps complete; report: ~s~n",
                      [maps:get(mapped_standards, Counts), length(Standards),
                       maps:get(mapped_pinned_specifications, Counts),
                       length(PinnedSpecifications), ?OUTPUT]),
            print_incomplete_diagnostics(IncompleteReports, BlockerSummary),
            erlang:error({incomplete_normative_requirement_map,
                          length(Incomplete), Incomplete})
    end.

blocker_summary(Reports) ->
    Counts = lists:foldl(fun(Report, Acc) ->
        lists:foldl(fun(Blocker, Inner) ->
            maps:update_with(Blocker, fun(Count) -> Count + 1 end, 1, Inner)
        end, Acc, maps:get(blockers, Report))
    end, #{}, Reports),
    Summaries = [#{blocker => Blocker, documents => Count}
                 || {Blocker, Count} <- maps:to_list(Counts)],
    lists:sort(fun(Left, Right) ->
        LeftCount = maps:get(documents, Left),
        RightCount = maps:get(documents, Right),
        case LeftCount =:= RightCount of
            true -> maps:get(blocker, Left) < maps:get(blocker, Right);
            false -> LeftCount > RightCount
        end
    end, Summaries).

print_incomplete_diagnostics(Reports, BlockerSummary) ->
    SummaryText = lists:join(", ", [
        io_lib:format("~ts=~B",
                      [maps:get(blocker, Entry), maps:get(documents, Entry)])
        || Entry <- BlockerSummary
    ]),
    io:format(standard_error, "incomplete blocker counts: ~s~n",
              [SummaryText]),
    io:format(standard_error, "incomplete requirement maps:~n", []),
    lists:foreach(fun(Report) ->
        Blockers = lists:join(",", maps:get(blockers, Report)),
        io:format(
            standard_error,
            "  ~ts: ~ts; requirements=~B, open=~B~n",
            [maps:get(id, Report), Blockers,
             maps:get(requirements, Report),
             maps:get(open_requirements, Report)]
        )
    end, Reports).

audit_policy(Policy) ->
    Roles = maps:get(<<"roles">>, Policy),
    Levels = maps:get(<<"levels">>, Policy),
    LegacyNormativeProse =
        maps:get(<<"legacy_normative_prose_standards">>, Policy),
    ensure(Roles =:= [<<"client">>, <<"server">>, <<"proxy">>,
                       <<"relay">>, <<"gateway">>],
           invalid_role_policy),
    ensure(Levels =:= requirement_levels(),
           invalid_requirement_level_policy),
    ensure(LegacyNormativeProse =:=
               [<<"RFC1950">>, <<"RFC1951">>, <<"RFC1952">>],
           invalid_legacy_normative_prose_policy),
    ReadyRule = maps:get(<<"ready_requires">>, Policy),
    ensure(is_binary(ReadyRule) andalso byte_size(ReadyRule) >= 40,
           invalid_ready_policy),
    #{roles => Roles,
      levels => Levels,
      legacy_normative_prose_standards => LegacyNormativeProse}.

audit_rfc_catalog(Catalog, Standards, Baseline) ->
    ensure(maps:get(<<"schema">>, Catalog) =:= 1,
           invalid_rfc_catalog_schema),
    Source = maps:get(<<"source">>, Catalog),
    ensure(is_map(Source), invalid_rfc_catalog_source),
    ensure(maps:get(<<"url">>, Source) =:=
               <<"https://www.rfc-editor.org/rfc-index.xml">>,
           untrusted_rfc_catalog_source),
    ensure(is_sha256(maps:get(<<"sha256">>, Source)),
           invalid_rfc_catalog_digest),
    ensure(maps:get(<<"baseline_date">>, Source) =:= Baseline,
           stale_rfc_catalog_baseline),
    RetrievedOn = maps:get(<<"retrieved_on">>, Source),
    ensure(is_iso_date(RetrievedOn), invalid_rfc_catalog_retrieval_date),
    ensure(RetrievedOn >= Baseline, rfc_catalog_predates_baseline),
    Entries = maps:get(<<"entries">>, Catalog),
    ensure(is_list(Entries) andalso Entries =/= [], empty_rfc_catalog),
    EntryIds = [maps:get(<<"id">>, Entry) || Entry <- Entries],
    ensure(length(EntryIds) =:= length(lists:usort(EntryIds)),
           duplicate_rfc_catalog_entry),
    lists:foreach(fun audit_rfc_catalog_entry/1, Entries),
    StandardIds = [maps:get(<<"id">>, Standard) || Standard <- Standards],
    ensure(lists:sort(EntryIds) =:= lists:sort(StandardIds),
           {rfc_catalog_inventory_drift,
            lists:sort(StandardIds), lists:sort(EntryIds)}),
    maps:from_list([
        {maps:get(<<"id">>, Entry), maps:get(<<"title">>, Entry)}
     || Entry <- Entries
    ]).

audit_rfc_catalog_entry(Entry) ->
    Id = maps:get(<<"id">>, Entry),
    ensure(re:run(Id, <<"^RFC[0-9]+$">>, [{capture, none}]) =:= match,
           {invalid_rfc_catalog_id, Id}),
    ensure_nonempty_binary(maps:get(<<"title">>, Entry),
                           {missing_rfc_catalog_title, Id}).

audit_rfc_identity(Standard, RfcCatalog) ->
    Id = maps:get(<<"id">>, Standard),
    ExpectedTitle = maps:get(Id, RfcCatalog),
    ActualTitle = maps:get(<<"title">>, Standard),
    ensure(ActualTitle =:= ExpectedTitle,
           {rfc_title_mismatch, Id, ExpectedTitle, ActualTitle}).

audit_standard(Standard, Policy, Baseline, Resolve) ->
    Id = maps:get(<<"id">>, Standard),
    ensure(re:run(Id, <<"^RFC[0-9]+$">>, [{capture, none}]) =:= match,
           {invalid_rfc_id, Id}),
    ensure_nonempty_binary(maps:get(<<"title">>, Standard),
                           {missing_title, Id}),
    Evidence = maps:get(<<"evidence">>, Standard),
    ensure(is_list(Evidence) andalso Evidence =/= [], {missing_evidence, Id}),
    lists:foreach(fun assert_file/1, Evidence),
    Complete = maps:get(<<"map_complete">>, Standard),
    ensure(is_boolean(Complete), {invalid_map_status, Id}),
    case Complete of
        true -> audit_completed_standard(Standard, Policy, Baseline, Resolve);
        false -> incomplete_standard_report(Standard, Policy, Baseline, Resolve)
    end.

audit_pinned_specification(Specification, Policy, Baseline, Resolve) ->
    Id = maps:get(<<"id">>, Specification),
    audit_pinned_specification_identity(Specification),
    Evidence = maps:get(<<"evidence">>, Specification),
    ensure(is_list(Evidence) andalso Evidence =/= [],
           {missing_evidence, Id}),
    lists:foreach(fun assert_file/1, Evidence),
    Complete = maps:get(<<"map_complete">>, Specification),
    ensure(is_boolean(Complete), {invalid_map_status, Id}),
    case Complete of
        true -> audit_completed_pinned_specification(
                    Specification, Policy, Baseline, Resolve);
        false -> incomplete_pinned_specification_report(
                     Specification, Policy, Baseline, Resolve)
    end.

audit_completed_pinned_specification(
    Specification, Policy, Baseline, Resolve
) ->
    Id = maps:get(<<"id">>, Specification),
    audit_pinned_specification_identity(Specification),
    audit_pinned_specification_source(
        Id, maps:get(<<"source">>, Specification), Baseline),
    Requirements = maps:get(<<"requirements">>, Specification),
    ensure(is_list(Requirements), {invalid_requirement_inventory, Id}),
    RequirementReports = audit_requirements(
        Id, Requirements, Policy, Resolve, false),
    NormativeLevels = audit_normative_inventory(
        Id, maps:get(<<"normative_inventory">>, Specification), Requirements,
        Policy),
    #{id => Id,
      title => maps:get(<<"title">>, Specification),
      kind => <<"PinnedInternetDraft">>,
      status => <<"Mapped">>,
      blockers => [],
      requirements => length(RequirementReports),
      implemented => count_disposition(<<"Implemented">>, RequirementReports),
      not_applicable => count_disposition(<<"NotApplicable">>,
                                          RequirementReports),
      deviations => count_disposition(<<"DocumentedDeviation">>,
                                      RequirementReports),
      open_requirements => 0,
      normative_levels => NormativeLevels,
      errata_reviewed => 0}.

incomplete_pinned_specification_report(
    Specification, Policy, Baseline, Resolve
) ->
    Id = maps:get(<<"id">>, Specification),
    audit_pinned_specification_identity(Specification),
    Blockers0 = [<<"map_not_complete">>],
    Blockers1 = case maps:find(<<"source">>, Specification) of
                    error -> [<<"source_not_pinned">> | Blockers0];
                    {ok, Source} ->
                        ok = audit_pinned_specification_source(
                            Id, Source, Baseline),
                        Blockers0
                end,
    Requirements = maps:get(<<"requirements">>, Specification, []),
    ensure(is_list(Requirements), {invalid_requirement_inventory, Id}),
    RequirementReports = case Requirements of
                             [] -> [];
                             _ -> audit_requirements(
                                 Id, Requirements, Policy, Resolve, true)
                         end,
    Blockers2 = case RequirementReports of
                    [] -> [<<"normative_requirements_not_enumerated">>
                           | Blockers1];
                    _ -> Blockers1
                end,
    OpenRequirements = count_disposition(<<"Open">>, RequirementReports),
    Blockers = case OpenRequirements of
                   0 -> Blockers2;
                   _ -> [<<"open_requirement_evidence">> | Blockers2]
               end,
    #{id => Id,
      title => maps:get(<<"title">>, Specification),
      kind => <<"PinnedInternetDraft">>,
      status => <<"Incomplete">>,
      blockers => lists:reverse(Blockers),
      requirements => length(RequirementReports),
      implemented => count_disposition(<<"Implemented">>, RequirementReports),
      not_applicable => count_disposition(<<"NotApplicable">>,
                                          RequirementReports),
      deviations => count_disposition(<<"DocumentedDeviation">>,
                                      RequirementReports),
      open_requirements => OpenRequirements,
      normative_levels => count_requirement_levels(Requirements),
      errata_reviewed => 0}.

audit_pinned_specification_identity(Specification) ->
    Id = maps:get(<<"id">>, Specification),
    ensure(re:run(Id, <<"^draft-[a-z0-9-]+-[0-9]{2}$">>,
                  [{capture, none}]) =:= match,
           {invalid_pinned_specification_id, Id}),
    ensure_nonempty_binary(maps:get(<<"title">>, Specification),
                           {missing_title, Id}),
    ensure(maps:get(<<"stability">>, Specification) =:= <<"WorkInProgress">>,
           {invalid_pinned_specification_stability, Id}).

audit_pinned_specification_source(Id, Source, Baseline) ->
    ensure(is_map(Source), {invalid_source_pin, Id}),
    ExpectedDocument = <<"https://www.ietf.org/archive/id/", Id/binary,
                         ".txt">>,
    Series = re:replace(Id, <<"-[0-9]{2}$">>, <<>>,
                        [{return, binary}]),
    ExpectedStatus = <<"https://datatracker.ietf.org/doc/", Series/binary,
                       "/">>,
    ensure(maps:get(<<"document_url">>, Source) =:= ExpectedDocument,
           {mutable_or_untrusted_pinned_source, Id}),
    ensure(maps:get(<<"status_url">>, Source) =:= ExpectedStatus,
           {untrusted_pinned_status_source, Id}),
    ensure(maps:get(<<"immutable_revision">>, Source) =:= true,
           {mutable_pinned_source, Id}),
    ensure(maps:get(<<"status">>, Source) =:= <<"ActiveInternetDraft">>,
           {invalid_pinned_source_status, Id}),
    ensure(maps:get(<<"reviewed_on">>, Source) =:= Baseline,
           {stale_source_review, Id}),
    PublishedOn = maps:get(<<"published_on">>, Source),
    ExpiresOn = maps:get(<<"expires_on">>, Source),
    ensure(is_iso_date(PublishedOn) andalso PublishedOn =< Baseline,
           {pinned_source_published_after_baseline, Id}),
    ensure(is_iso_date(ExpiresOn) andalso ExpiresOn > Baseline,
           {pinned_source_expired_at_baseline, Id}),
    ensure(is_sha256(maps:get(<<"document_sha256">>, Source)),
           {invalid_pinned_source_digest, Id}),
    ok.

audit_completed_standard(Standard, Policy, Baseline, Resolve) ->
    Id = maps:get(<<"id">>, Standard),
    audit_source(Id, maps:get(<<"source">>, Standard), Baseline),
    Requirements = maps:get(<<"requirements">>, Standard),
    ensure(is_list(Requirements), {invalid_requirement_inventory, Id}),
    RequirementReports = audit_requirements(
        Id, Requirements, Policy, Resolve, false),
    NormativeLevels = audit_normative_inventory(
        Id, maps:get(<<"normative_inventory">>, Standard), Requirements,
        Policy),
    ErrataCount = audit_errata(Id, maps:get(<<"errata">>, Standard),
                               Baseline, Resolve),
    #{id => Id,
      title => maps:get(<<"title">>, Standard),
      status => <<"Mapped">>,
      blockers => [],
      requirements => length(RequirementReports),
      implemented => count_disposition(<<"Implemented">>, RequirementReports),
      not_applicable => count_disposition(<<"NotApplicable">>,
                                          RequirementReports),
      deviations => count_disposition(<<"DocumentedDeviation">>,
                                      RequirementReports),
      open_requirements => 0,
      normative_levels => NormativeLevels,
      errata_reviewed => ErrataCount}.

incomplete_standard_report(Standard, Policy, Baseline, Resolve) ->
    Id = maps:get(<<"id">>, Standard),
    Blockers0 = [<<"map_not_complete">>],
    Blockers1 = case maps:find(<<"source">>, Standard) of
                    error -> [<<"source_not_pinned">> | Blockers0];
                    {ok, Source} ->
                        ok = audit_source(Id, Source, Baseline),
                        Blockers0
                end,
    Requirements = maps:get(<<"requirements">>, Standard, []),
    ensure(is_list(Requirements), {invalid_requirement_inventory, Id}),
    RequirementReports = case Requirements of
                             [] -> [];
                             _ -> audit_requirements(
                                 Id, Requirements, Policy, Resolve, true)
                         end,
    Blockers2 = case RequirementReports of
                    [] -> [<<"normative_requirements_not_enumerated">>
                           | Blockers1];
                    _ -> Blockers1
                end,
    OpenRequirements = count_disposition(<<"Open">>, RequirementReports),
    BlockersWithRequirements = case OpenRequirements of
                                   0 -> Blockers2;
                                   _ -> [<<"open_requirement_evidence">>
                                         | Blockers2]
                               end,
    {Blockers3, ErrataCount} = case maps:find(<<"errata">>, Standard) of
                    {ok, Errata} when is_map(Errata) ->
                        case maps:get(<<"inventory_complete">>, Errata, false) of
                            true ->
                                Count = audit_errata(Id, Errata, Baseline,
                                                     Resolve),
                                {BlockersWithRequirements, Count};
                            false ->
                                {[<<"errata_inventory_not_complete">>
                                  | BlockersWithRequirements], 0}
                        end;
                    _ -> {[<<"errata_inventory_not_complete">>
                           | BlockersWithRequirements],
                          0}
                end,
    #{id => Id,
      title => maps:get(<<"title">>, Standard),
      status => <<"Incomplete">>,
      blockers => lists:reverse(Blockers3),
      requirements => length(RequirementReports),
      implemented => count_disposition(<<"Implemented">>, RequirementReports),
      not_applicable => count_disposition(<<"NotApplicable">>,
                                          RequirementReports),
      deviations => count_disposition(<<"DocumentedDeviation">>,
                                      RequirementReports),
      open_requirements => OpenRequirements,
      normative_levels => count_requirement_levels(Requirements),
      errata_reviewed => ErrataCount}.

audit_normative_inventory(StandardId, Inventory, Requirements, Policy) ->
    ensure(is_map(Inventory),
           {invalid_normative_inventory, StandardId}),
    Convention = maps:get(<<"keyword_convention">>, Inventory,
                          <<"BCP14Uppercase">>),
    Scope = maps:get(<<"scope">>, Inventory),
    case Convention of
        <<"BCP14Uppercase">> ->
            ensure(Scope =:= ?NORMATIVE_SCOPE,
                   {invalid_normative_inventory_scope, StandardId});
        <<"LegacyNormativeProse">> ->
            ensure(lists:member(
                       StandardId,
                       maps:get(legacy_normative_prose_standards,
                                Policy, [])),
                   {legacy_normative_prose_not_allowed, StandardId}),
            ensure(Scope =:= ?LEGACY_NORMATIVE_SCOPE,
                   {invalid_normative_inventory_scope, StandardId});
        _ -> erlang:error(
                 {invalid_normative_keyword_convention,
                  StandardId, Convention})
    end,
    Expected = maps:get(<<"expected_total">>, Inventory),
    ensure(is_integer(Expected) andalso Expected >= 0,
           {invalid_normative_requirement_count, StandardId}),
    Declared = maps:get(<<"level_counts">>, Inventory),
    ensure(is_map(Declared),
           {invalid_normative_level_counts, StandardId}),
    ensure((Expected =:= 0 andalso map_size(Declared) =:= 0)
           orelse (Expected > 0 andalso map_size(Declared) > 0),
           {invalid_normative_level_counts, StandardId}),
    maps:foreach(fun(Level, Count) ->
        ensure(lists:member(Level, maps:get(levels, Policy)),
               {invalid_normative_inventory_level, StandardId, Level}),
        ensure(is_integer(Count) andalso Count > 0,
               {invalid_normative_inventory_level_count,
                StandardId, Level, Count})
    end, Declared),
    Actual = count_requirement_levels(Requirements),
    ensure(Expected =:= length(Requirements),
           {normative_requirement_count_drift, StandardId, Expected,
            length(Requirements)}),
    ensure(Declared =:= Actual,
           {normative_requirement_level_drift, StandardId, Declared, Actual}),
    Declared.

count_requirement_levels(Requirements) ->
    lists:foldl(fun(Requirement, Counts) ->
        Level = maps:get(<<"level">>, Requirement),
        maps:update_with(Level, fun(Count) -> Count + 1 end, 1, Counts)
    end, #{}, Requirements).

audit_source(Id, Source, Baseline) ->
    ensure(is_map(Source), {invalid_source_pin, Id}),
    Number = binary:part(Id, 3, byte_size(Id) - 3),
    ExpectedDocument = <<"https://www.rfc-editor.org/rfc/rfc",
                         Number/binary, ".txt">>,
    ExpectedErrata = <<"https://errata.rfc-editor.org/search/?rfc_number=",
                       Number/binary>>,
    ensure(maps:get(<<"document_url">>, Source) =:= ExpectedDocument,
           {untrusted_rfc_source, Id}),
    ensure(maps:get(<<"errata_url">>, Source) =:= ExpectedErrata,
           {untrusted_errata_source, Id}),
    ensure(maps:get(<<"reviewed_on">>, Source) =:= Baseline,
           {stale_source_review, Id}),
    Digest = maps:get(<<"document_sha256">>, Source),
    ensure(is_sha256(Digest), {invalid_rfc_digest, Id}),
    ok.

audit_requirements(StandardId, Requirements, Policy, Resolve, AllowOpen) ->
    RequirementIds = [maps:get(<<"id">>, Requirement)
                      || Requirement <- Requirements],
    ensure(length(RequirementIds) =:= length(lists:usort(RequirementIds)),
           {duplicate_requirement, StandardId}),
    [audit_requirement(StandardId, Requirement, Policy, Resolve, AllowOpen)
     || Requirement <- Requirements].

audit_requirement(StandardId, Requirement, Policy, Resolve, AllowOpen) ->
    Id = maps:get(<<"id">>, Requirement),
    Prefix = <<StandardId/binary, "-">>,
    ensure(binary:match(Id, Prefix) =:= {0, byte_size(Prefix)},
           {invalid_requirement_id, StandardId, Id}),
    ensure_nonempty_binary(maps:get(<<"section">>, Requirement),
                           {missing_requirement_section, Id}),
    Level = maps:get(<<"level">>, Requirement),
    ensure(lists:member(Level, maps:get(levels, Policy)),
           {invalid_requirement_level, Id, Level}),
    Roles = maps:get(<<"roles">>, Requirement),
    ensure(is_list(Roles) andalso Roles =/= [],
           {missing_requirement_roles, Id}),
    ensure(length(Roles) =:= length(lists:usort(Roles)),
           {duplicate_requirement_role, Id}),
    lists:foreach(fun(Role) ->
        ensure(lists:member(Role, maps:get(roles, Policy)),
               {invalid_requirement_role, Id, Role})
    end, Roles),
    ensure_minimum_text(maps:get(<<"summary">>, Requirement), 20,
                        {insufficient_requirement_summary, Id}),
    Disposition = maps:get(<<"disposition">>, Requirement),
    case Disposition of
        <<"Implemented">> ->
            Implementations = required_references(<<"implementation">>,
                                                  Requirement, Id),
            Tests = required_references(<<"tests">>, Requirement, Id),
            lists:foreach(Resolve, Implementations ++ Tests);
        <<"NotApplicable">> ->
            ensure_minimum_text(maps:get(<<"reason">>, Requirement), 30,
                                {missing_not_applicable_reason, Id}),
            ensure(maps:get(<<"implementation">>, Requirement, []) =:= [],
                   {not_applicable_has_implementation, Id}),
            ensure(maps:get(<<"tests">>, Requirement, []) =:= [],
                   {not_applicable_has_tests, Id});
        <<"DocumentedDeviation">> ->
            ensure(lists:member(Level, advisory_levels()),
                   {mandatory_requirement_deviation, Id}),
            ensure_minimum_text(maps:get(<<"reason">>, Requirement), 30,
                                {missing_deviation_reason, Id}),
            Tests = required_references(<<"tests">>, Requirement, Id),
            Implementations = maps:get(<<"implementation">>, Requirement, []),
            ensure(is_list(Implementations),
                   {invalid_evidence_references, Id}),
            lists:foreach(Resolve, Implementations ++ Tests);
        <<"Open">> ->
            ensure(AllowOpen, {open_requirement_in_completed_map, Id}),
            ensure_minimum_text(maps:get(<<"reason">>, Requirement), 30,
                                {missing_open_requirement_reason, Id}),
            Implementations = maps:get(<<"implementation">>, Requirement, []),
            Tests = maps:get(<<"tests">>, Requirement, []),
            ensure(is_list(Implementations) andalso is_list(Tests),
                   {invalid_evidence_references, Id}),
            lists:foreach(Resolve, Implementations ++ Tests);
        _ -> erlang:error({invalid_requirement_disposition, Id, Disposition})
    end,
    #{id => Id, disposition => Disposition}.

required_references(Key, Requirement, Id) ->
    References = maps:get(Key, Requirement),
    ensure(is_list(References) andalso References =/= [],
           {missing_requirement_evidence, Id, Key}),
    References.

audit_errata(StandardId, Errata, Baseline, Resolve) ->
    ensure(is_map(Errata), {invalid_errata_inventory, StandardId}),
    ensure(maps:get(<<"inventory_complete">>, Errata) =:= true,
           {incomplete_errata_inventory, StandardId}),
    ensure(maps:get(<<"checked_on">>, Errata) =:= Baseline,
           {stale_errata_review, StandardId}),
    Entries = maps:get(<<"entries">>, Errata),
    Expected = maps:get(<<"expected_total">>, Errata),
    ensure(is_integer(Expected) andalso Expected >= 0,
           {invalid_errata_count, StandardId}),
    ensure(is_list(Entries) andalso length(Entries) =:= Expected,
           {errata_count_drift, StandardId, Expected, length_or_invalid(Entries)}),
    Ids = [maps:get(<<"id">>, Entry) || Entry <- Entries],
    ensure(length(Ids) =:= length(lists:usort(Ids)),
           {duplicate_erratum, StandardId}),
    lists:foreach(fun(Entry) ->
        audit_erratum(StandardId, Entry, Resolve)
    end, Entries),
    length(Entries).

audit_erratum(StandardId, Entry, Resolve) ->
    Id = maps:get(<<"id">>, Entry),
    ensure(is_integer(Id) andalso Id > 0, {invalid_erratum_id, StandardId, Id}),
    ensure_nonempty_binary(maps:get(<<"section">>, Entry),
                           {missing_erratum_section, Id}),
    ensure(lists:member(maps:get(<<"status">>, Entry),
                        [<<"Verified">>, <<"Reported">>, <<"Held for "
                          "Document Update">>, <<"Rejected">>]),
           {invalid_erratum_status, Id}),
    ensure(lists:member(maps:get(<<"type">>, Entry),
                        [<<"Editorial">>, <<"Technical">>]),
           {invalid_erratum_type, Id}),
    ensure(lists:member(maps:get(<<"disposition">>, Entry),
                        [<<"Accepted">>, <<"Reviewed">>, <<"Rejected">>]),
           {invalid_erratum_disposition, Id}),
    ensure_minimum_text(maps:get(<<"reason">>, Entry), 20,
                        {missing_erratum_reason, Id}),
    Impact = maps:get(<<"behavior_impact">>, Entry),
    ensure(is_boolean(Impact), {invalid_erratum_impact, Id}),
    case Impact of
        true ->
            Implementations = required_errata_references(
                <<"implementation">>, Entry, Id),
            Tests = required_errata_references(<<"tests">>, Entry, Id),
            lists:foreach(Resolve, Implementations ++ Tests);
        false ->
            ensure(maps:get(<<"implementation">>, Entry, []) =:= [],
                   {editorial_erratum_has_implementation, Id}),
            ensure(maps:get(<<"tests">>, Entry, []) =:= [],
                   {editorial_erratum_has_tests, Id})
    end.

required_errata_references(Key, Entry, Id) ->
    References = maps:get(Key, Entry),
    ensure(is_list(References) andalso References =/= [],
           {missing_erratum_evidence, Id, Key}),
    References.

assert_evidence_reference(Reference) when is_map(Reference) ->
    Path = maps:get(<<"path">>, Reference),
    Symbol = maps:get(<<"symbol">>, Reference),
    assert_file(Path),
    ensure_nonempty_binary(Symbol, {empty_evidence_symbol, Path}),
    ensure(re:run(Symbol, <<"^[A-Za-z][A-Za-z0-9_]*(/[0-9]+)?$">>,
                  [{capture, none}]) =:= match,
           {invalid_evidence_symbol, Path, Symbol}),
    BaseSymbol = hd(binary:split(Symbol, <<"/">>)),
    {ok, Bytes} = file:read_file(binary_to_list(Path)),
    ensure(symbol_present(BaseSymbol, Bytes),
           {missing_evidence_symbol, Path, Symbol});
assert_evidence_reference(Reference) ->
    erlang:error({invalid_evidence_reference, Reference}).

symbol_present(Symbol, Bytes) ->
    Pattern = <<"(^|[^A-Za-z0-9_])", Symbol/binary,
                "([^A-Za-z0-9_]|$)">>,
    re:run(Bytes, Pattern, [multiline, {capture, none}]) =:= match.

audit_registry(Registry, Baseline) ->
    ensure(maps:get(<<"checked_on">>, Registry) =:= Baseline,
           stale_registry_review),
    ensure(maps:get(<<"permanent_only">>, Registry) =:= true,
           provisional_registry_values_allowed),
    ensure(is_boolean(maps:get(<<"complete">>, Registry)),
           invalid_registry_status),
    lists:foreach(fun assert_file/1, maps:get(<<"evidence">>, Registry)).

report_counts(StandardReports, PinnedReports) ->
    AllReports = StandardReports ++ PinnedReports,
    #{standards => length(StandardReports),
      mapped_standards => count_status(<<"Mapped">>, StandardReports),
      incomplete_standards => count_status(<<"Incomplete">>, StandardReports),
      pinned_specifications => length(PinnedReports),
      mapped_pinned_specifications =>
          count_status(<<"Mapped">>, PinnedReports),
      incomplete_pinned_specifications =>
          count_status(<<"Incomplete">>, PinnedReports),
      requirements => sum_field(requirements, AllReports),
      implemented => sum_field(implemented, AllReports),
      not_applicable => sum_field(not_applicable, AllReports),
      documented_deviations => sum_field(deviations, AllReports),
      open_requirements => sum_field(open_requirements, AllReports),
      errata_reviewed => sum_field(errata_reviewed, StandardReports)}.

count_status(Status, Reports) ->
    length([ok || Report <- Reports, maps:get(status, Report) =:= Status]).

count_disposition(Disposition, Reports) ->
    length([ok || Report <- Reports,
                 maps:get(disposition, Report) =:= Disposition]).

sum_field(Field, Reports) ->
    lists:sum([maps:get(Field, Report) || Report <- Reports]).

length_or_invalid(Value) when is_list(Value) -> length(Value);
length_or_invalid(_Value) -> invalid.

self_test() ->
    Policy = #{roles => [<<"client">>, <<"server">>],
               levels => requirement_levels(),
               legacy_normative_prose_standards => [<<"RFC1950">>]},
    Resolve = fun(_Reference) -> ok end,
    Valid = self_test_standard(),
    RfcCatalog = #{
        <<"RFC7464">> =>
            <<"JavaScript Object Notation (JSON) Text Sequences">>
    },
    ok = audit_rfc_identity(Valid, RfcCatalog),
    expect_error(
        mismatched_rfc_identity,
        {rfc_title_mismatch, <<"RFC7464">>,
         <<"JavaScript Object Notation (JSON) Text Sequences">>,
         <<"RateLimit Fields for HTTP">>},
        fun() ->
            audit_rfc_identity(
                Valid#{<<"title">> => <<"RateLimit Fields for HTTP">>},
                RfcCatalog
            )
        end
    ),
    Pinned = self_test_pinned_specification(),
    PinnedReport = audit_completed_pinned_specification(
        Pinned, Policy, ?BASELINE_DATE, Resolve
    ),
    ensure(maps:get(status, PinnedReport) =:= <<"Mapped">>,
           self_test_valid_pinned_specification_rejected),
    expect_error(
        mutable_pinned_specification,
        {invalid_pinned_specification_id,
         <<"draft-ietf-httpapi-ratelimit-headers">>},
        fun() ->
            audit_completed_pinned_specification(
                Pinned#{
                    <<"id">> => <<"draft-ietf-httpapi-ratelimit-headers">>
                },
                Policy,
                ?BASELINE_DATE,
                Resolve
            )
        end
    ),
    Report = audit_completed_standard(Valid, Policy, ?BASELINE_DATE, Resolve),
    ensure(maps:get(status, Report) =:= <<"Mapped">>, self_test_valid_rejected),
    ZeroNormative = Valid#{
        <<"requirements">> => [],
        <<"normative_inventory">> => #{
            <<"scope">> => ?NORMATIVE_SCOPE,
            <<"expected_total">> => 0,
            <<"level_counts">> => #{}
        }
    },
    ZeroReport = audit_completed_standard(
        ZeroNormative, Policy, ?BASELINE_DATE, Resolve),
    ensure(maps:get(requirements, ZeroReport) =:= 0,
           self_test_zero_normative_map_rejected),
    [LegacyRequirement] = maps:get(<<"requirements">>, Valid),
    LegacyInventory = #{
        <<"keyword_convention">> => <<"LegacyNormativeProse">>,
        <<"scope">> => ?LEGACY_NORMATIVE_SCOPE,
        <<"expected_total">> => 1,
        <<"level_counts">> => #{<<"MUST">> => 1}
    },
    LegacyLevels = audit_normative_inventory(
        <<"RFC1950">>, LegacyInventory, [LegacyRequirement], Policy),
    ensure(LegacyLevels =:= #{<<"MUST">> => 1},
           self_test_legacy_normative_prose_rejected),
    expect_error(
        legacy_prose_not_allowlisted,
        {legacy_normative_prose_not_allowed, <<"RFC7464">>},
        fun() -> audit_normative_inventory(
            <<"RFC7464">>, LegacyInventory, [LegacyRequirement], Policy)
        end
    ),
    expect_error(empty_requirements,
                 {normative_requirement_count_drift, <<"RFC7464">>, 1, 0},
                 fun() -> audit_completed_standard(
                     Valid#{<<"requirements">> => []}, Policy,
                     ?BASELINE_DATE, Resolve)
                 end),
    [Requirement] = maps:get(<<"requirements">>, Valid),
    BadRole = Requirement#{<<"roles">> => [<<"observer">>]},
    expect_error(invalid_role,
                 {invalid_requirement_role, maps:get(<<"id">>, Requirement),
                  <<"observer">>},
                 fun() -> audit_completed_standard(
                     Valid#{<<"requirements">> => [BadRole]}, Policy,
                     ?BASELINE_DATE, Resolve)
                 end),
    NotApplicable = maps:without([<<"implementation">>, <<"tests">>],
                                 Requirement#{
                                     <<"disposition">> => <<"NotApplicable">>,
                                     <<"reason">> => <<"short">>
                                 }),
    expect_error(weak_not_applicable_reason,
                 {missing_not_applicable_reason,
                  maps:get(<<"id">>, Requirement)},
                 fun() -> audit_completed_standard(
                     Valid#{<<"requirements">> => [NotApplicable]}, Policy,
                     ?BASELINE_DATE, Resolve)
                 end),
    MandatoryDeviation = Requirement#{
        <<"disposition">> => <<"DocumentedDeviation">>,
        <<"reason">> => <<"This reason is deliberately long enough to pass.">>
    },
    expect_error(mandatory_deviation,
                 {mandatory_requirement_deviation,
                  maps:get(<<"id">>, Requirement)},
                 fun() -> audit_completed_standard(
                     Valid#{<<"requirements">> => [MandatoryDeviation]},
                     Policy, ?BASELINE_DATE, Resolve)
                 end),
    RequiredDeviation = MandatoryDeviation#{<<"level">> => <<"REQUIRED">>},
    expect_error(required_alias_is_mandatory,
                 {mandatory_requirement_deviation,
                  maps:get(<<"id">>, Requirement)},
                 fun() -> audit_completed_standard(
                     Valid#{<<"requirements">> => [RequiredDeviation]},
                     Policy, ?BASELINE_DATE, Resolve)
                 end),
    Recommended = Requirement#{<<"level">> => <<"RECOMMENDED">>},
    RecommendedReport = audit_completed_standard(
        with_self_test_requirements(Valid, [Recommended]), Policy,
        ?BASELINE_DATE, Resolve),
    ensure(maps:get(implemented, RecommendedReport) =:= 1,
           self_test_recommended_alias_rejected),
    NotRecommendedDeviation = MandatoryDeviation#{
        <<"level">> => <<"NOT RECOMMENDED">>
    },
    NotRecommendedReport = audit_completed_standard(
        with_self_test_requirements(Valid, [NotRecommendedDeviation]), Policy,
        ?BASELINE_DATE, Resolve),
    ensure(maps:get(deviations, NotRecommendedReport) =:= 1,
           self_test_not_recommended_alias_rejected),
    Inventory = maps:get(<<"normative_inventory">>, Valid),
    BadInventory = Inventory#{<<"expected_total">> => 2},
    expect_error(normative_count_drift,
                 {normative_requirement_count_drift, <<"RFC7464">>, 2, 1},
                 fun() -> audit_completed_standard(
                     Valid#{<<"normative_inventory">> => BadInventory},
                     Policy, ?BASELINE_DATE, Resolve)
                 end),
    Errata = maps:get(<<"errata">>, Valid),
    expect_error(errata_count_drift,
                 {errata_count_drift, <<"RFC7464">>, 1, 0},
                 fun() -> audit_completed_standard(
                     Valid#{<<"errata">> => Errata#{<<"expected_total">> => 1}},
                     Policy, ?BASELINE_DATE, Resolve)
                 end),
    MissingResolve = fun(_Reference) -> erlang:error(missing_test_symbol) end,
    expect_error(missing_symbol, missing_test_symbol,
                 fun() -> audit_completed_standard(
                     Valid, Policy, ?BASELINE_DATE, MissingResolve)
                 end),
    BadPartial = Valid#{<<"map_complete">> => false,
                        <<"requirements">> => [BadRole]},
    expect_error(invalid_partial_role,
                 {invalid_requirement_role, maps:get(<<"id">>, Requirement),
                  <<"observer">>},
                 fun() -> incomplete_standard_report(
                     BadPartial, Policy, ?BASELINE_DATE, Resolve)
                 end),
    OpenRequirement = Requirement#{
        <<"disposition">> => <<"Open">>,
        <<"reason">> =>
            <<"Wire-level executable evidence remains deliberately open.">>,
        <<"implementation">> => [],
        <<"tests">> => []
    },
    expect_error(open_in_completed_map,
                 {open_requirement_in_completed_map,
                  maps:get(<<"id">>, Requirement)},
                 fun() -> audit_completed_standard(
                     Valid#{<<"requirements">> => [OpenRequirement]},
                     Policy, ?BASELINE_DATE, Resolve)
                 end),
    PartialReport = incomplete_standard_report(
        Valid#{<<"map_complete">> => false,
               <<"requirements">> => [OpenRequirement]},
        Policy, ?BASELINE_DATE, Resolve),
    ensure(maps:get(open_requirements, PartialReport) =:= 1,
           self_test_open_requirement_not_counted),
    ensure(lists:member(<<"open_requirement_evidence">>,
                        maps:get(blockers, PartialReport)),
           self_test_open_requirement_blocker_missing),
    [#{blocker := <<"map_not_complete">>, documents := 2},
     #{blocker := <<"open_requirement_evidence">>, documents := 1},
     #{blocker := <<"source_not_pinned">>, documents := 1}] =
        blocker_summary([
            #{blockers => [<<"map_not_complete">>, <<"source_not_pinned">>]},
            #{blockers => [<<"map_not_complete">>,
                           <<"open_requirement_evidence">>]}
        ]),
    io:format(
      "requirements audit schema self-test ok (13 adversarial cases, two "
      "alias acceptance cases, one legacy-prose acceptance case, and an "
      "explicit zero-clause map)~n", []),
    ok.

requirement_levels() ->
    [<<"MUST">>, <<"MUST NOT">>, <<"REQUIRED">>, <<"SHALL">>,
     <<"SHALL NOT">>, <<"SHOULD">>, <<"SHOULD NOT">>,
     <<"RECOMMENDED">>, <<"NOT RECOMMENDED">>].

advisory_levels() ->
    [<<"SHOULD">>, <<"SHOULD NOT">>, <<"RECOMMENDED">>,
     <<"NOT RECOMMENDED">>].

self_test_standard() ->
    Reference = #{<<"path">> => <<"fixture.gleam">>,
                  <<"symbol">> => <<"fixture_test">>},
    #{<<"id">> => <<"RFC7464">>,
      <<"title">> =>
          <<"JavaScript Object Notation (JSON) Text Sequences">>,
      <<"map_complete">> => true,
      <<"source">> => #{
          <<"document_url">> =>
              <<"https://www.rfc-editor.org/rfc/rfc7464.txt">>,
          <<"document_sha256">> =>
              <<"a8eadbcdce5fc508b9e014299621562da041232af13848632092164d50b3f482">>,
          <<"errata_url">> =>
              <<"https://errata.rfc-editor.org/search/?rfc_number=7464">>,
          <<"reviewed_on">> => ?BASELINE_DATE
      },
      <<"requirements">> => [#{
          <<"id">> => <<"RFC7464-2-MUST-UTF8">>,
          <<"section">> => <<"2">>,
          <<"level">> => <<"MUST">>,
          <<"roles">> => [<<"client">>, <<"server">>],
          <<"summary">> =>
              <<"JSON text sequences use UTF-8 for every encoded record.">>,
          <<"disposition">> => <<"Implemented">>,
          <<"implementation">> => [Reference],
          <<"tests">> => [Reference]
      }],
      <<"normative_inventory">> => #{
          <<"scope">> => ?NORMATIVE_SCOPE,
          <<"expected_total">> => 1,
          <<"level_counts">> => #{<<"MUST">> => 1}
      },
      <<"errata">> => #{
          <<"inventory_complete">> => true,
          <<"checked_on">> => ?BASELINE_DATE,
          <<"expected_total">> => 0,
          <<"entries">> => []
      }}.

self_test_pinned_specification() ->
    Standard = self_test_standard(),
    [Requirement] = maps:get(<<"requirements">>, Standard),
    Id = <<"draft-ietf-httpapi-ratelimit-headers-11">>,
    maps:without([<<"errata">>], Standard#{
        <<"id">> => Id,
        <<"title">> => <<"RateLimit header fields for HTTP">>,
        <<"stability">> => <<"WorkInProgress">>,
        <<"source">> => #{
            <<"document_url">> =>
                <<"https://www.ietf.org/archive/id/", Id/binary, ".txt">>,
            <<"document_sha256">> =>
                <<"d6016dd0db5a33ba3f1e6b6f4c84e9b5ecc00986822d5212bab831f6c2d1d412">>,
            <<"status_url">> =>
                <<"https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/">>,
            <<"immutable_revision">> => true,
            <<"status">> => <<"ActiveInternetDraft">>,
            <<"published_on">> => <<"2026-05-23">>,
            <<"expires_on">> => <<"2026-11-24">>,
            <<"reviewed_on">> => ?BASELINE_DATE
        },
        <<"requirements">> => [Requirement#{
            <<"id">> => <<Id/binary, "-3-MUST-STRING">>
        }]
    }).

with_self_test_requirements(Standard, Requirements) ->
    Standard#{
        <<"requirements">> => Requirements,
        <<"normative_inventory">> => #{
            <<"scope">> => ?NORMATIVE_SCOPE,
            <<"expected_total">> => length(Requirements),
            <<"level_counts">> => count_requirement_levels(Requirements)
        }
    }.

expect_error(Label, Expected, Run) ->
    try Run() of
        _ -> erlang:error({self_test_expected_failure, Label})
    catch
        error:Expected -> ok;
        error:Other -> erlang:error({self_test_wrong_failure,
                                     Label, Expected, Other})
    end.

assert_file(Path) when is_binary(Path) ->
    case filelib:is_regular(binary_to_list(Path)) of
        true -> ok;
        false -> erlang:error({missing_evidence_file, Path})
    end;
assert_file(Path) ->
    erlang:error({invalid_evidence_path, Path}).

is_sha256(Digest) when is_binary(Digest) ->
    re:run(Digest, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match;
is_sha256(_Digest) ->
    false.

is_iso_date(Date) when is_binary(Date) ->
    re:run(Date, <<"^[0-9]{4}-[0-9]{2}-[0-9]{2}$">>,
           [{capture, none}]) =:= match;
is_iso_date(_Date) ->
    false.

ensure_nonempty_binary(Value, Reason) ->
    ensure(is_binary(Value) andalso byte_size(Value) > 0, Reason).

ensure_minimum_text(Value, Minimum, Reason) ->
    ensure(is_binary(Value) andalso byte_size(Value) >= Minimum, Reason).

decode(Path) ->
    {ok, Bytes} = file:read_file(Path),
    try json:decode(Bytes) of
        Value when is_map(Value) -> Value
    catch
        _:_ -> erlang:error({invalid_json, Path})
    end.

write_report(Report) ->
    ok = filelib:ensure_dir(?OUTPUT),
    file:write_file(?OUTPUT, [json:encode(Report), <<"\n">>]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
