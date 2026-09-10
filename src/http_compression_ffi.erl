-module(http_compression_ffi).

-export([compress/4, decompress/7]).

-define(INVALID, 1).
-define(LIMIT, 2).
-define(UNAVAILABLE, 3).
-define(DICTIONARY, 4).

-spec compress(integer(), binary(), binary(), integer()) ->
    {ok, binary()} | {error, 1 | 2 | 3 | 4}.
compress(1, Input, <<>>, Level) when is_binary(Input), is_integer(Level) ->
    zlib_compress(Input, Level, 31, <<>>);
compress(2, Input, Dictionary, Level)
    when is_binary(Input), is_binary(Dictionary), is_integer(Level) ->
    zlib_compress(Input, Level, 15, Dictionary);
compress(4, Input, Dictionary, Level)
    when is_binary(Input), is_binary(Dictionary), is_integer(Level) ->
    zstd_compress(Input, Dictionary, Level);
compress(_, _, _, _) ->
    {error, ?INVALID}.

-spec decompress(integer(), binary(), binary(), integer(), integer(), integer(),
                 integer()) ->
    {ok, binary()} | {error, 1 | 2 | 3 | 4}.
decompress(1, Input, <<>>, MaximumOutput, MaximumRatio, MaximumWork, _WindowLog)
    when is_binary(Input), is_integer(MaximumOutput), is_integer(MaximumRatio),
         is_integer(MaximumWork) ->
    zlib_decompress(Input, <<>>, 31, MaximumOutput, MaximumRatio, MaximumWork);
decompress(2, Input, Dictionary, MaximumOutput, MaximumRatio, MaximumWork,
           _WindowLog)
    when is_binary(Input), is_binary(Dictionary), is_integer(MaximumOutput),
         is_integer(MaximumRatio), is_integer(MaximumWork) ->
    zlib_decompress(Input, Dictionary, 15, MaximumOutput, MaximumRatio,
                    MaximumWork);
decompress(4, Input, Dictionary, MaximumOutput, MaximumRatio, MaximumWork,
           WindowLog)
    when is_binary(Input), is_binary(Dictionary), is_integer(MaximumOutput),
         is_integer(MaximumRatio), is_integer(MaximumWork),
         is_integer(WindowLog) ->
    zstd_decompress(Input, Dictionary, MaximumOutput, MaximumRatio, MaximumWork,
                    WindowLog);
decompress(_, _, _, _, _, _, _) ->
    {error, ?INVALID}.

-spec zlib_compress(binary(), integer(), integer(), binary()) ->
    {ok, binary()} | {error, 1 | 3 | 4}.
zlib_compress(Input, Level, WindowBits, Dictionary)
    when Level >= 0, Level =< 9 ->
    Z = zlib:open(),
    try
        ok = zlib:deflateInit(Z, Level, deflated, WindowBits, 8, default),
        case Dictionary of
            <<>> -> ok;
            _ when WindowBits =:= 15 ->
                _ = zlib:deflateSetDictionary(Z, Dictionary),
                ok;
            _ -> throw(dictionary_not_supported)
        end,
        Output = iolist_to_binary(zlib:deflate(Z, Input, finish)),
        ok = zlib:deflateEnd(Z),
        {ok, Output}
    catch
        throw:dictionary_not_supported -> {error, ?DICTIONARY};
        _:_ -> {error, ?INVALID}
    after
        safe_deflate_end(Z),
        zlib:close(Z)
    end;
zlib_compress(_, _, _, _) ->
    {error, ?INVALID}.

-spec zlib_decompress(binary(), binary(), integer(), integer(), integer(),
                      integer()) ->
    {ok, binary()} | {error, 1 | 2 | 3 | 4}.
zlib_decompress(Input, Dictionary, WindowBits, MaximumOutput, MaximumRatio,
                MaximumWork)
    when MaximumOutput >= 0, MaximumRatio > 0, MaximumWork > 0 ->
    Z = zlib:open(),
    try
        %% `cut` (the OTP default) silently discards bytes after the first
        %% wrapper. A one-shot HTTP decoder must reject that ambiguity. gzip
        %% legitimately permits concatenated members, so reset for its
        %% wrapper and require a clean end; zlib has exactly one member.
        EoSBehavior = case WindowBits of
            31 -> reset;
            _ -> error
        end,
        ok = zlib:inflateInit(Z, WindowBits, EoSBehavior),
        Allowed = allowed_output(byte_size(Input), MaximumOutput, MaximumRatio),
        Result = zlib_inflate_loop(
            Z, zlib:safeInflate(Z, Input), Dictionary, Allowed, MaximumWork,
            0, []
        ),
        ok = zlib:inflateEnd(Z),
        Result
    catch
        throw:limit -> {error, ?LIMIT};
        throw:dictionary -> {error, ?DICTIONARY};
        _:_ -> {error, ?INVALID}
    after
        safe_inflate_end(Z),
        zlib:close(Z)
    end;
zlib_decompress(_, _, _, _, _, _) ->
    {error, ?INVALID}.

-spec zlib_inflate_loop(zlib:zstream(), tuple(), binary(), non_neg_integer(),
                        pos_integer(), non_neg_integer(), [binary()]) ->
    {ok, binary()}.
zlib_inflate_loop(_Z, _Result, _Dictionary, _Allowed, 0, _Total, _Reversed) ->
    throw(limit);
zlib_inflate_loop(Z, {continue, Output}, Dictionary, Allowed, Work, Total,
                  Reversed) ->
    {NextTotal, NextReversed} = retain_output(Output, Allowed, Total, Reversed),
    zlib_inflate_loop(Z, zlib:safeInflate(Z, []), Dictionary, Allowed,
                      Work - 1, NextTotal, NextReversed);
zlib_inflate_loop(_Z, {finished, Output}, _Dictionary, Allowed, _Work, Total,
                  Reversed) ->
    {_NextTotal, NextReversed} = retain_output(Output, Allowed, Total, Reversed),
    {ok, iolist_to_binary(lists:reverse(NextReversed))};
zlib_inflate_loop(_Z, {need_dictionary, _Adler32, Output}, <<>>, Allowed, _Work,
                  Total, Reversed) ->
    _ = retain_output(Output, Allowed, Total, Reversed),
    throw(dictionary);
zlib_inflate_loop(Z, {need_dictionary, _Adler32, Output}, Dictionary, Allowed,
                  Work, Total, Reversed) ->
    {NextTotal, NextReversed} = retain_output(Output, Allowed, Total, Reversed),
    ok = zlib:inflateSetDictionary(Z, Dictionary),
    zlib_inflate_loop(Z, zlib:safeInflate(Z, []), Dictionary, Allowed,
                      Work - 1, NextTotal, NextReversed).

-spec zstd_compress(binary(), binary(), integer()) ->
    {ok, binary()} | {error, 1 | 3 | 4}.
zstd_compress(Input, Dictionary, Level) when Level >= -22, Level =< 22 ->
    case code:ensure_loaded(zstd) of
        {module, zstd} ->
            Options0 = #{compressionLevel => Level, pledgedSrcSize => byte_size(Input)},
            Options = maybe_dictionary(Dictionary, Options0),
            try zstd:compress(Input, Options) of
                Output -> {ok, iolist_to_binary(Output)}
            catch
                _:_ -> {error, ?INVALID}
            end;
        _ ->
            {error, ?UNAVAILABLE}
    end;
zstd_compress(_, _, _) ->
    {error, ?INVALID}.

-spec zstd_decompress(binary(), binary(), integer(), integer(), integer(),
                      integer()) ->
    {ok, binary()} | {error, 1 | 2 | 3 | 4}.
zstd_decompress(Input, Dictionary, MaximumOutput, MaximumRatio, MaximumWork,
                WindowLog)
    when MaximumOutput >= 0, MaximumRatio > 0, MaximumWork > 0,
         WindowLog >= 10, WindowLog =< 31 ->
    case code:ensure_loaded(zstd) of
        {module, zstd} ->
            Allowed = allowed_output(byte_size(Input), MaximumOutput, MaximumRatio),
            Options = maybe_dictionary(Dictionary, #{windowLogMax => WindowLog}),
            try
                reject_declared_zstd_size(Input, Allowed),
                {ok, Context} = zstd:context(decompress, Options),
                try
                    zstd_stream_loop(Context, Input, Allowed, MaximumWork, 0, [])
                after
                    zstd:close(Context)
                end
            catch
                throw:limit -> {error, ?LIMIT};
                _:_ -> {error, ?INVALID}
            end;
        _ ->
            {error, ?UNAVAILABLE}
    end;
zstd_decompress(_, _, _, _, _, _) ->
    {error, ?INVALID}.

-spec reject_declared_zstd_size(binary(), non_neg_integer()) -> ok.
reject_declared_zstd_size(Input, Allowed) ->
    case zstd:get_frame_header(Input) of
        {ok, #{frameContentSize := Size}} when is_integer(Size), Size > Allowed ->
            throw(limit);
        _ ->
            ok
    end.

-spec zstd_stream_loop(zstd:context(), iodata(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(), [binary()]) ->
    {ok, binary()}.
zstd_stream_loop(_Context, _Input, _Allowed, 0, _Total, _Reversed) ->
    throw(limit);
zstd_stream_loop(Context, Input, Allowed, Work, Total, Reversed) ->
    case zstd:stream(Context, Input) of
        {continue, Remainder, Output} ->
            {NextTotal, NextReversed} =
                retain_output(Output, Allowed, Total, Reversed),
            zstd_stream_loop(Context, Remainder, Allowed, Work - 1, NextTotal,
                             NextReversed);
        {continue, Output} ->
            {NextTotal, NextReversed} =
                retain_output(Output, Allowed, Total, Reversed),
            {done, FinalOutput} = zstd:finish(Context, <<>>),
            {_FinalTotal, FinalReversed} = retain_output(
                FinalOutput, Allowed, NextTotal, NextReversed
            ),
            {ok, iolist_to_binary(lists:reverse(FinalReversed))}
    end.

-spec maybe_dictionary(binary(), map()) -> map().
maybe_dictionary(<<>>, Options) -> Options;
maybe_dictionary(Dictionary, Options) -> Options#{dictionary => Dictionary}.

-spec safe_deflate_end(zlib:zstream()) -> ok.
safe_deflate_end(Z) ->
    try zlib:deflateEnd(Z) of
        ok -> ok
    catch
        _:_ -> ok
    end.

-spec safe_inflate_end(zlib:zstream()) -> ok.
safe_inflate_end(Z) ->
    try zlib:inflateEnd(Z) of
        ok -> ok
    catch
        _:_ -> ok
    end.

-spec allowed_output(non_neg_integer(), non_neg_integer(), pos_integer()) ->
    non_neg_integer().
allowed_output(CompressedBytes, MaximumOutput, MaximumRatio) ->
    RatioLimit = CompressedBytes * MaximumRatio,
    erlang:min(MaximumOutput, RatioLimit).

-spec retain_output(iodata(), non_neg_integer(), non_neg_integer(), [binary()]) ->
    {non_neg_integer(), [binary()]}.
retain_output(Output, Allowed, Total, Reversed) ->
    Size = iolist_size(Output),
    NextTotal = Total + Size,
    case NextTotal =< Allowed of
        true ->
            case Size of
                0 -> {NextTotal, Reversed};
                _ -> {NextTotal, [iolist_to_binary(Output) | Reversed]}
            end;
        false ->
            throw(limit)
    end.
