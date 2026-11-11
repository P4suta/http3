%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% These controls mutate real tar bytes and rebind both pass digests. An
%% unchanged source inventory and correct checksum must not hide metadata drift.
archive_metadata_self_test() ->
    Directory = release_directory(hex(crypto:strong_rand_bytes(16))),
    put(release_directory, Directory),
    make_output(Directory),
    Package = lists:last(release_packages()),
    [Artifact] = compare_passes([build_archive(Package, "pass-a")],
                               [build_archive(Package, "pass-b")]),
    install_archive(Artifact, filename:join(Directory, "registry")),
    Expected = lists:last(release_expected()),
    archive_metadata_rejection_tests(Artifact, Expected, Directory).

archive_metadata_rejection_tests(Artifact0, Expected, Directory) ->
    Artifact = json_map(Artifact0),
    Name = binary_to_list(maps:get(name, Expected)),
    Paths = [filename:join([Directory, Pass, Name ++ "-0.1.0.tar"]) ||
        Pass <- ["pass-a", "pass-b"]],
    Original = read(hd(Paths)),
    Check = fun(A) -> release_archive_valid(A, Expected, Directory) end,
    ok = Check(Artifact),
    Changes = [{mode, 100, <<"0000600", 0>>},
               {mtime, 136, <<"00000000001", 0>>},
               {uid, 108, <<"0000001", 0>>},
               {gid, 116, <<"0000001", 0>>}],
    Rows = [begin
        Forged = archive_metadata_mutation(Original, Layer, Offset, Field),
        Rebound = Artifact#{<<"sha256">> => hex(crypto:hash(sha256, Forged)),
                            <<"bytes">> => byte_size(Forged)},
        Rejected = try
            lists:foreach(fun(P) -> ok = file:write_file(P, Forged) end, Paths),
            rejected(fun() -> Check(Rebound) end)
        after
            lists:foreach(fun(P) -> ok = file:write_file(P, Original) end, Paths)
        end,
        ok = Check(Artifact),
        #{layer => Layer, field => Label, rejected => Rejected}
    end || Layer <- [outer, inner], {Label, Offset, Field} <- Changes],
    write_json(filename:join(Directory, "metadata-controls.json"), #{schema => 1,
        actual_retained_consumer => true, positive_archive_valid => true,
        execution_environment => execution_runtime(), tests => Rows}),
    ensure(lists:all(fun(#{rejected := R}) -> R end, Rows),
           forged_archive_metadata_accepted),
    io:format("archive metadata: 8 rebound mutations rejected~n").

archive_metadata_mutation(Bytes, outer, Offset, Field) ->
    archive_metadata_header(Bytes, Offset, Field);
archive_metadata_mutation(Bytes, inner, Offset, Field) ->
    {ok, Outer} = erl_tar:extract({binary, Bytes}, [memory]),
    Version = member("VERSION", Outer), Metadata = member("metadata.config", Outer),
    Contents = zlib:gzip(archive_metadata_header(
        zlib:gunzip(member("contents.tar.gz", Outer)), Offset, Field)),
    Checksum = hex(crypto:hash(sha256, [Version, Metadata, Contents])),
    Path = filename:join(output(), "metadata-mutation.tar"),
    try
        ok = erl_tar:create(Path, [{"VERSION", Version}, {"metadata.config", Metadata},
            {"contents.tar.gz", Contents}, {"CHECKSUM", Checksum}],
            [{mtime, 0}, {atime, 0}, {ctime, 0}, {uid, 0}, {gid, 0}, {mode, 8#100644}]),
        read(Path)
    after _ = file:delete(Path) end.

archive_metadata_header(<<Header:512/binary, Rest/binary>>, Offset, Field) ->
    Length = byte_size(Field),
    <<Before:Offset/binary, _:Length/binary, After/binary>> = Header,
    Patched = <<Before/binary, Field/binary, After/binary>>,
    <<Start:148/binary, _:8/binary, End/binary>> = Patched,
    Sum = lists:sum(binary_to_list(<<Start/binary, "        ", End/binary>>)),
    Octal = integer_to_binary(Sum, 8),
    Padding = binary:copy(<<"0">>, 6 - byte_size(Octal)),
    <<Start/binary, Padding/binary, Octal/binary, 0, 32, End/binary, Rest/binary>>.
