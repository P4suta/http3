%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_INTEROP_GO_EVIDENCE_HRL).
-define(HTTP_INTEROP_GO_EVIDENCE_HRL,true).
-include_lib("kernel/include/file.hrl").

%% Compiler and toolchain hashes below are observations by the owned producer,
%% not signatures or retained copies of the external Go distribution. Imported
%% Linux evidence must not be compared with a Windows auditor's Go installation.
%% The retained peer executable itself is mandatory and its buildinfo is parsed
%% independently. A structurally valid synthetic map is never retained evidence.
interop_go_receipt_shape(Peer,Identity,Inputs,Module)->
    interop_keys(Identity,[<<"kind">>,<<"executable">>,<<"version">>,<<"lock_sha256">>,
        <<"fixture_sha256">>,<<"dependencies">>,<<"build">>]),
    interop_ensure(maps:get(<<"kind">>,Identity)=:= <<"go">>,wrong_go_identity_kind),
    interop_ensure(maps:get(<<"version">>,Identity)=:=maps:get(<<"go_version">>,Peer),wrong_go_compiler_version),
    Build=maps:get(<<"build">>,Identity),
    interop_keys(Build,[<<"schema">>,<<"status">>,<<"peer">>,<<"nonce">>,<<"sources">>,<<"recipes">>,
        <<"lock">>,<<"compiler">>,<<"toolchain">>,<<"binary">>,<<"module_info">>,<<"steps">>]),
    interop_ensure(maps:get(<<"schema">>,Build)=:=1 andalso maps:get(<<"status">>,Build)=:= <<"Passed">>,
        incomplete_go_build_receipt),
    interop_ensure(maps:get(<<"peer">>,Build)=:=maps:get(<<"id">>,Peer),wrong_go_build_peer),
    interop_text(maps:get(<<"nonce">>,Build),<<"^[0-9a-f]{32}$">>),
    lists:foreach(fun(Key)->interop_ensure(maps:get(Key,Build)=:=maps:get(Key,Inputs),stale_go_build_inputs) end,
        [<<"sources">>,<<"recipes">>,<<"lock">>]),
    interop_go_rows(maps:get(<<"sources">>,Build),256,1048576),
    interop_go_rows(maps:get(<<"recipes">>,Build),5,268435456),
    lists:foreach(fun(Key)->interop_go_file_digest_shape(maps:get(Key,Build),1) end,
        [<<"compiler">>,<<"binary">>,<<"lock">>]),
    interop_ensure(maps:get(<<"binary">>,Build)=:=maps:get(<<"executable">>,Identity),go_binary_identity_mismatch),
    LockHash=maps:get(<<"sha256">>,maps:get(<<"lock">>,Build)),
    interop_ensure(LockHash=:=maps:get(<<"lock_sha256">>,Identity)
        andalso LockHash=:=maps:get(<<"lock_sha256">>,Peer),go_dependency_lock_mismatch),
    interop_ensure(maps:get(<<"fixture_sha256">>,Identity)=:=
        interop_go_rows_digest(maps:get(<<"sources">>,Build)),go_fixture_digest_mismatch),
    Tools=maps:get(<<"toolchain">>,Build),interop_keys(Tools,[<<"sha256">>,<<"files">>]),
    interop_go_hash(maps:get(<<"sha256">>,Tools)),interop_integer(maps:get(<<"files">>,Tools),1,20000),
    Steps=maps:get(<<"steps">>,Build),Names=[<<"download">>,<<"verify_before">>,<<"build">>,<<"verify_after">>],
    interop_ensure(is_list(Steps) andalso length(Steps)=:=4,incomplete_go_build_steps),
    lists:foreach(fun({Step,Name})->interop_go_step(Step,Name) end,lists:zip(Steps,Names)),
    Info=maps:get(<<"module_info">>,Build),interop_go_module_info(Peer,Info,Module),
    Expected=[#{<<"name">>=>maps:get(<<"name">>,D),<<"version">>=>maps:get(<<"version">>,D),
        <<"sha256">>=>interop_bytes_digest(maps:get(<<"sum">>,D)),<<"files">>=>0}
        ||D<-maps:get(<<"dependencies">>,Info)],
    interop_ensure(Expected=:=maps:get(<<"dependencies">>,Identity),go_dependency_identity_mismatch),ok.

interop_go_audit_identity(Peer,Identity)->
    Inputs=interop_go_inputs(Peer),{Directory,_,BinaryName}=interop_go_peer(maps:get(<<"id">>,Peer)),
    Module=interop_go_module_name(interop_go_read(Directory++"/go.mod",1048576)),
    interop_go_receipt_shape(Peer,Identity,Inputs,Module),
    Build=maps:get(<<"build">>,Identity),
    Id=binary_to_list(maps:get(<<"id">>,Peer)),
    ReceiptPath="build/interop/go-build/"++Id++".json",
    AttemptPath="build/interop/go-build/"++Id++"-attempt.json",
    Retained=evidence_json_decode(interop_go_read(ReceiptPath,1048576)),
    interop_ensure(Retained=:=Build,missing_or_replaced_go_build_receipt),
    Attempt=evidence_json_decode(interop_go_read(AttemptPath,1024)),
    interop_go_attempt(Attempt,maps:get(<<"id">>,Peer),maps:get(<<"nonce">>,Build)),
    Bytes=interop_go_read("build/interop/bin/"++BinaryName,268435456),
    interop_ensure(interop_go_digest(Bytes)=:=maps:get(<<"binary">>,Build),replaced_go_executable),
    Info=interop_go_elf_info(Bytes),
    interop_ensure(Info=:=maps:get(<<"module_info">>,Build),go_executable_module_info_mismatch),
    Lock=interop_go_read(binary_to_list(maps:get(<<"lock">>,Peer)),1048576),
    Locked=binary:split(Lock,<<"\n">>,[global]),
    lists:foreach(fun(D)->Line= <<(maps:get(<<"name">>,D))/binary," ",
        (maps:get(<<"version">>,D))/binary," ",(maps:get(<<"sum">>,D))/binary>>,
        interop_ensure(lists:member(Line,[string:trim(L)||L<-Locked]),go_dependency_not_locked)
    end,maps:get(<<"dependencies">>,Info)),
    interop_ensure(Inputs=:=interop_go_inputs(Peer),go_inputs_changed_during_audit),ok.

interop_go_attempt(Attempt,Peer,Nonce)->
    interop_ensure(Attempt=:=#{<<"schema">>=>1,<<"peer">>=>Peer,<<"nonce">>=>Nonce},stale_go_build_attempt),ok.
interop_go_step(Step,Name)->
    interop_keys(Step,[<<"step">>,<<"outcome">>,<<"exit_status">>,<<"exit_observed">>,
        <<"controlled_shutdown">>,<<"elapsed_milliseconds">>,<<"stdout_bytes">>,<<"stderr_bytes">>]),
    interop_ensure(maps:get(<<"step">>,Step)=:=Name andalso maps:get(<<"outcome">>,Step)=:= <<"completed">>
        andalso maps:get(<<"exit_status">>,Step)=:=0 andalso maps:get(<<"exit_observed">>,Step)=:=true
        andalso maps:get(<<"controlled_shutdown">>,Step)=:=false,failed_go_build_step),
    interop_integer(maps:get(<<"elapsed_milliseconds">>,Step),0,125000),
    interop_integer(maps:get(<<"stdout_bytes">>,Step),0,1048576),
    interop_integer(maps:get(<<"stderr_bytes">>,Step),0,1048576),
    interop_ensure(maps:get(<<"stdout_bytes">>,Step)+maps:get(<<"stderr_bytes">>,Step)=<1048576,oversized_go_build_output).

interop_go_module_info(Peer,Info,Module)->
    interop_keys(Info,[<<"version">>,<<"path">>,<<"module">>,<<"dependencies">>,<<"settings">>]),
    interop_ensure(maps:get(<<"version">>,Info)=:=maps:get(<<"go_version">>,Peer),wrong_go_module_compiler),
    interop_ensure(maps:get(<<"path">>,Info)=:=Module andalso maps:get(<<"module">>,Info)=:=Module,wrong_go_main_module),
    interop_text(Module,<<"^[A-Za-z0-9][A-Za-z0-9._/+~-]{0,191}$">>),
    Deps=maps:get(<<"dependencies">>,Info),interop_go_ordered_rows(Deps,1,128),
    lists:foreach(fun(D)->
        interop_keys(D,[<<"name">>,<<"version">>,<<"sum">>]),
        interop_text(maps:get(<<"name">>,D),<<"^[A-Za-z0-9][A-Za-z0-9._/+~-]{0,191}$">>),
        interop_text(maps:get(<<"version">>,D),<<"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$">>),
        interop_text(maps:get(<<"sum">>,D),<<"^h1:[A-Za-z0-9+/]{43}=$">>)
    end,Deps),
    interop_ensure(lists:any(fun(D)-> <<(maps:get(<<"name">>,D))/binary,"@",
        (maps:get(<<"version">>,D))/binary>>=:=maps:get(<<"pin">>,Peer) end,Deps),go_pinned_module_missing),
    Settings=maps:get(<<"settings">>,Info),interop_go_ordered_rows(Settings,6,32),
    Allowed=[<<"-buildmode">>,<<"-compiler">>,<<"-trimpath">>,<<"CGO_ENABLED">>,<<"GOARCH">>,<<"GOOS">>,
        <<"GOAMD64">>,<<"GOARM64">>,<<"GOARM">>,<<"GO386">>,<<"GOMIPS">>,<<"GOMIPS64">>,<<"GOPPC64">>,<<"GORISCV64">>,<<"DefaultGODEBUG">>],
    lists:foreach(fun(S)->interop_keys(S,[<<"name">>,<<"value">>]),
        interop_ensure(lists:member(maps:get(<<"name">>,S),Allowed),unknown_go_build_setting),
        interop_go_setting(maps:get(<<"name">>,S),maps:get(<<"value">>,S)) end,Settings),
    Map=maps:from_list([{maps:get(<<"name">>,S),maps:get(<<"value">>,S)}||S<-Settings]),
    Required=#{<<"-buildmode">>=><<"exe">>,<<"-compiler">>=><<"gc">>,<<"-trimpath">>=><<"true">>,<<"CGO_ENABLED">>=><<"0">>},
    interop_ensure(maps:with(maps:keys(Required),Map)=:=Required andalso maps:is_key(<<"GOARCH">>,Map)
        andalso maps:is_key(<<"GOOS">>,Map),uncontrolled_go_build_settings),ok.
interop_go_setting(<<"DefaultGODEBUG">>,Value)->
    interop_ensure(is_binary(Value) andalso byte_size(Value)>0 andalso byte_size(Value)=<4096,oversized_go_defaults),
    Pairs=binary:split(Value,<<",">>,[global]),interop_integer(length(Pairs),1,128),
    Names=[begin [Name,Setting]=binary:split(Pair,<<"=">>,[global]),
        interop_text(Name,<<"^[a-z][a-z0-9]{0,63}$">>),interop_text(Setting,<<"^[0-9]{1,10}$">>),Name end||Pair<-Pairs],
    interop_ensure(length(Names)=:=length(lists:usort(Names)),duplicate_go_default);
interop_go_setting(_,Value)->interop_text(Value,<<"^[A-Za-z0-9][A-Za-z0-9.,_+-]{0,63}$">>).
interop_go_ordered_rows(Rows,Minimum,Maximum)->
    interop_ensure(is_list(Rows) andalso length(Rows)>=Minimum andalso length(Rows)=<Maximum,invalid_go_row_count),
    Names=[maps:get(<<"name">>,R)||R<-Rows],
    interop_ensure(Names=:=lists:usort(Names),duplicate_or_unordered_go_rows).
interop_go_rows(Rows,Maximum,MaximumBytes)->
    interop_ensure(is_list(Rows) andalso length(Rows)>0 andalso length(Rows)=<Maximum,invalid_go_input_inventory),
    Names=[maps:get(<<"path">>,R)||R<-Rows],interop_ensure(Names=:=lists:usort(Names),duplicate_or_unordered_go_inputs),
    lists:foreach(fun(R)->interop_keys(R,[<<"path">>,<<"sha256">>,<<"bytes">>]),
        Name=maps:get(<<"path">>,R),interop_ensure(is_binary(Name) andalso byte_size(Name)>0 andalso byte_size(Name)=<1024,invalid_go_input_path),
        interop_go_hash(maps:get(<<"sha256">>,R)),interop_integer(maps:get(<<"bytes">>,R),0,MaximumBytes) end,Rows),ok.
interop_go_file_digest_shape(D,Minimum)->
    interop_keys(D,[<<"sha256">>,<<"bytes">>]),interop_go_hash(maps:get(<<"sha256">>,D)),
    interop_integer(maps:get(<<"bytes">>,D),Minimum,268435456).
interop_go_hash(H)->interop_text(H,<<"^[a-f0-9]{64}$">>).
interop_go_digest(B)->#{<<"sha256">>=>interop_bytes_digest(B),<<"bytes">>=>byte_size(B)}.

interop_go_peer(<<"quic-go-h3">>)->{"packages/http3/test/interop/quicgo","packages/http3/test/interop/run.sh","quic-go"};
interop_go_peer(<<"ohttp-go">>)->{"test/interop/ohttpgo","test/interop/ohttpgo/setup.sh","ohttp-go"};
interop_go_peer(<<"masque-independent">>)->{"test/interop/masquego","test/interop/masquego/setup.sh","masque-go"}.
interop_go_inputs(Peer)->
    {Directory,Recipe,_}=interop_go_peer(maps:get(<<"id">>,Peer)),
    Sources=lists:sort(interop_go_walk([Directory],0,[])),
    interop_ensure(length(Sources)>0 andalso length(Sources)=<256,invalid_go_source_count),
    LockPath=Directory++"/go.sum",
    interop_ensure(maps:get(<<"lock">>,Peer)=:=list_to_binary(LockPath)
        andalso lists:member(LockPath,Sources) andalso lists:member(Directory++"/go.mod",Sources),missing_go_module_inputs),
    Recipes=["scripts/interop_go_build.py","scripts/interop_peer.py","standards/interop-profile.json",Recipe]++
        case filename:basename(Recipe) of "setup.sh"->[Directory++"/run.sh"];_->[] end,
    Lock=interop_go_digest(interop_go_read(LockPath,1048576)),
    interop_ensure(maps:get(<<"sha256">>,Lock)=:=maps:get(<<"lock_sha256">>,Peer),go_lock_drift),
    #{<<"sources">>=>interop_go_inventory(Sources,1048576),<<"recipes">>=>interop_go_inventory(Recipes,268435456),<<"lock">>=>Lock}.
interop_go_walk([],_,Sources)->Sources;
interop_go_walk([Directory|Rest],Visited,Sources)->
    interop_ensure(Visited<256 andalso length(Rest)=<256 andalso length(Sources)=<256,too_many_go_sources),
    interop_go_parents(Directory,directory),{ok,Names}=file:list_dir(Directory),
    interop_ensure(length(Names)=<4096,too_many_go_directory_entries),
    {Folders,Next}=lists:foldl(fun(Name,{Ds,Fs})->
        Path=Directory++"/"++Name,{ok,Info}=file:read_link_info(Path),
        case Info#file_info.type of
            directory->{[Path|Ds],Fs};
            regular->interop_go_supported_suffix(Name),
                case filename:extension(Name)=:= ".go" orelse lists:member(Name,["go.mod","go.sum"]) of
                    false->{Ds,Fs};
                    true->interop_ensure(length(Fs)<256,too_many_go_sources),
                        Bytes=interop_go_read(Path,1048576),
                        case filename:extension(Name) of ".go"->interop_go_source(Bytes);_->ok end,{Ds,[Path|Fs]}
                end;
            _->erlang:error(unsafe_go_source_entry)
        end
    end,{Rest,Sources},Names),interop_go_walk(Folders,Visited+1,Next).
interop_go_supported_suffix(Name)->
    Bad=[".s",".syso",".c",".h",".cc",".hh",".cpp",".hpp",".cxx",".hxx",".m",".mm",".f",".for",".f90",".swig",".swigcxx"],
    interop_ensure(not lists:member(string:lowercase(filename:extension(Name)),Bad),unbound_go_native_input).
interop_go_source(Bytes)->
    interop_ensure(binary:match(Bytes,<<"//go:embed">>)=:=nomatch,unbound_go_embedded_input),
    %% Fixed pure-Go fixtures reject any string literal denoting C. Tokenize
    %% comments and runes separately so URL text cannot hide a later literal.
    Pattern= <<"//[^\\n]*|/\\*.*?\\*/|\"(?:\\\\.|[^\"\\\\])*\"|`[^`]*`|'(?:\\\\.|[^'\\\\])*'">>,
    Tokens=case re:run(Bytes,Pattern,[global,dotall,{capture,first,binary}]) of
        nomatch->[];{match,Matches}->[Token||[Token]<-Matches]
    end,
    C=[<<"\"C\"">>,<<"\"\\x43\"">>,<<"\"\\u0043\"">>,<<"\"\\U00000043\"">>,<<"\"\\103\"">>],
    lists:foreach(fun(Token)->interop_ensure(not lists:member(Token,C)
        andalso binary:replace(Token,<<"\r">>,<<>>,[global])=/= <<"`C`">>,unbound_go_cgo_import) end,Tokens).
interop_go_inventory(Names,Maximum)->
    [begin B=interop_go_read(Name,Maximum),(interop_go_digest(B))#{<<"path">>=>unicode:characters_to_binary(Name)} end||Name<-lists:sort(Names)].
interop_go_read(Path,Maximum)->
    interop_go_parents(Path,regular),{ok,F}=file:open(Path,[read,binary,raw]),
    try case file:read(F,Maximum+1) of
        {ok,B} when byte_size(B)=<Maximum->B;
        eof-> <<>>;
        _->erlang:error(oversized_or_invalid_go_artifact)
    end after file:close(F) end.
interop_go_parents(Path,FinalType)->
    Parts=filename:split(Path),interop_ensure(length(Parts)>0 andalso length(Parts)=<256,unsafe_go_input_path),
    interop_go_parent_parts(Parts,"",FinalType).
interop_go_parent_parts([Part|Rest],Prefix,FinalType)->
    interop_ensure(Part=/="." andalso Part=/=".." andalso filename:pathtype(Part)=:=relative,unsafe_go_input_path),
    Path=case Prefix of ""->Part;_->Prefix++"/"++Part end,
    {ok,Info}=file:read_link_info(Path),Expected=case Rest of []->FinalType;_->directory end,
    interop_ensure(Info#file_info.type=:=Expected,unsafe_go_input_type),
    case Rest of []->ok;_->interop_go_parent_parts(Rest,Path,FinalType) end.
interop_go_module_name(Bytes)->
    {match,[Module]}=re:run(Bytes,<<"(?m)^module[ \\t]+([A-Za-z0-9][A-Za-z0-9._/+~-]{0,191})[ \\t]*\\r?$">>,[{capture,[1],binary}]),Module.

%% Linux fixtures use ELF64 little-endian executables. Parse only the named,
%% mapped .go.buildinfo section; a magic-looking string elsewhere is not proof.
%% Inline framing follows https://go.dev/src/debug/buildinfo/buildinfo.go .
interop_go_elf_info(Bytes) when is_binary(Bytes),byte_size(Bytes)=<268435456->
    <<127,"ELF",2,1,1,_:9/binary,Type:16/little,Machine:16/little,1:32/little,
        _Entry:64/little,PhOff:64/little,ShOff:64/little,_Flags:32/little,
        64:16/little,56:16/little,PhCount:16/little,64:16/little,ShCount:16/little,
        NamesIndex:16/little,_/binary>>=Bytes,
    interop_ensure(Type=:=2 andalso lists:member(Machine,[62,183]),unsupported_go_executable_platform),
    interop_integer(ShCount,1,256),interop_integer(NamesIndex,1,ShCount-1),interop_integer(PhCount,1,128),
    Headers=interop_go_slice(Bytes,ShOff,ShCount*64),
    Sections=[interop_go_section(S)||<<S:64/binary>><=Headers],
    NameSection=lists:nth(NamesIndex+1,Sections),
    interop_ensure(maps:get(type,NameSection)=:=3,invalid_go_section_name_table),
    Strings=interop_go_section_bytes(Bytes,NameSection,1048576),
    [Section]=[S||S<-Sections,interop_go_elf_name(Strings,maps:get(name,S))=:= <<".go.buildinfo">>],
    interop_ensure(maps:get(type,Section)=:=1 andalso maps:get(flags,Section)=:=3
        andalso maps:get(offset,Section) rem 16=:=0,invalid_go_buildinfo_section),
    Programs=interop_go_slice(Bytes,PhOff,PhCount*56),
    interop_ensure(lists:any(fun(P)->interop_go_mapped(P,Section,byte_size(Bytes)) end,
        [P||<<P:56/binary>><=Programs]),unmapped_go_buildinfo_section),
    Blob=interop_go_section_bytes(Bytes,Section,1048576),
    <<255," Go buildinf:",8,2,0:128,Inline/binary>>=Blob,
    {Version,AfterVersion}=interop_go_inline_string(Inline,64),
    {Framed,Tail}=interop_go_inline_string(AfterVersion,1048576),
    interop_ensure(byte_size(Tail)=<15 andalso Tail=:=binary:copy(<<0>>,byte_size(Tail)),extra_go_buildinfo_data),
    interop_ensure(byte_size(Framed)>=33,invalid_go_module_framing),
    Length=byte_size(Framed)-32,<<_:16/binary,Module:Length/binary,_:16/binary>>=Framed,
    interop_ensure(binary:last(Module)=:=$\n,invalid_go_module_framing),
    interop_go_parse_info(Version,Module);
interop_go_elf_info(_)->erlang:error(invalid_go_executable_buildinfo).
interop_go_section(<<Name:32/little,Type:32/little,Flags:64/little,Address:64/little,
        Offset:64/little,Size:64/little,_:24/binary>>)->
    #{name=>Name,type=>Type,flags=>Flags,address=>Address,offset=>Offset,size=>Size}.
interop_go_slice(Bytes,Offset,Size)->
    interop_ensure(Offset>=0 andalso Size>=0 andalso Offset+Size=<byte_size(Bytes),truncated_go_executable),
    binary:part(Bytes,Offset,Size).
interop_go_section_bytes(Bytes,Section,Maximum)->
    Size=maps:get(size,Section),interop_integer(Size,1,Maximum),interop_go_slice(Bytes,maps:get(offset,Section),Size).
interop_go_elf_name(Strings,Offset)->
    interop_integer(Offset,0,byte_size(Strings)-1),
    Scope=erlang:min(256,byte_size(Strings)-Offset),
    {End,1}=binary:match(Strings,<<0>>,[{scope,{Offset,Scope}}]),binary:part(Strings,Offset,End-Offset).
interop_go_mapped(<<Type:32/little,Flags:32/little,Offset:64/little,Address:64/little,
        _Physical:64/little,Size:64/little,_Memory:64/little,_Align:64/little>>,Section,Total)->
    At=maps:get(offset,Section),Length=maps:get(size,Section),
    Type=:=1 andalso Flags band 2=:=2 andalso Offset+Size=<Total
        andalso At>=Offset andalso At+Length=<Offset+Size
        andalso maps:get(address,Section)=:=Address+At-Offset.
interop_go_inline_string(Bytes,Maximum)->
    {Length,Rest}=interop_go_varint(Bytes,0,0),interop_integer(Length,1,Maximum),
    interop_ensure(byte_size(Rest)>=Length,truncated_go_buildinfo_string),
    <<Value:Length/binary,Tail/binary>>=Rest,{Value,Tail}.
interop_go_varint(<<Byte,Rest/binary>>,Shift,Value) when Shift=<63->
    N=Value bor ((Byte band 127) bsl Shift),
    case Byte band 128 of
        0->interop_ensure((Shift=:=0 orelse Byte=/=0) andalso N=<9223372036854775807,invalid_go_buildinfo_varint),{N,Rest};
        _->interop_go_varint(Rest,Shift+7,N)
    end;
interop_go_varint(_,_,_)->erlang:error(invalid_go_buildinfo_varint).
interop_go_parse_info(Version,Module)->
    Lines=[L||L<-binary:split(Module,<<"\n">>,[global]),L=/= <<>>],
    interop_ensure(length(Lines)>0 andalso length(Lines)=<164,oversized_go_module_info),
    Initial=#{<<"version">>=>Version,<<"path">>=>null,<<"module">>=>null,<<"dependencies">>=>[],<<"settings">>=>[]},
    Result=lists:foldl(fun(Line,State)->
        interop_go_info_row(re:split(string:trim(Line),<<"\\s+">>,[{return,binary}]),State)
    end,Initial,Lines),
    Result#{<<"dependencies">>:=lists:sort(fun(A,B)->maps:get(<<"name">>,A)<maps:get(<<"name">>,B) end,maps:get(<<"dependencies">>,Result)),
        <<"settings">>:=lists:sort(fun(A,B)->maps:get(<<"name">>,A)<maps:get(<<"name">>,B) end,maps:get(<<"settings">>,Result))}.
interop_go_info_row([<<"path">>,Path],State=#{<<"path">>:=null})->State#{<<"path">>:=Path};
interop_go_info_row([<<"mod">>,Module,<<"(devel)">>],State=#{<<"module">>:=null})->State#{<<"module">>:=Module};
interop_go_info_row([<<"dep">>,Name,Version,Sum],State)->State#{<<"dependencies">>:=
    [#{<<"name">>=>Name,<<"version">>=>Version,<<"sum">>=>Sum}|maps:get(<<"dependencies">>,State)]};
interop_go_info_row([<<"build">>,Pair],State)->[Name,Value]=binary:split(Pair,<<"=">>),
    State#{<<"settings">>:=[#{<<"name">>=>Name,<<"value">>=>Value}|maps:get(<<"settings">>,State)]};
interop_go_info_row(_,_)->erlang:error(invalid_go_module_info_row).
interop_go_rows_digest(Rows)->
    interop_bytes_digest([<<"http-go-build-files-v1",0,(length(Rows)):64/unsigned-big>>|
        [begin Name=maps:get(<<"path">>,R),Size=maps:get(<<"bytes">>,R),
            Hash=binary:decode_hex(maps:get(<<"sha256">>,R)),
            <<(byte_size(Name)):64/unsigned-big,Name/binary,Size:64/unsigned-big,Hash/binary>> end||R<-Rows]]).
-endif.
