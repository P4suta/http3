%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(http_cookie_ffi).

-export([parse_cookie_date/1, unix_seconds/0]).

-define(MAXIMUM_DATE_BYTES, 8192).
-define(UNIX_EPOCH_GREGORIAN_SECONDS, 62167219200).

-spec unix_seconds() -> integer().
unix_seconds() ->
    erlang:system_time(second).

-spec parse_cookie_date(binary()) -> {ok, integer()} | {error, nil}.
parse_cookie_date(Value)
    when is_binary(Value), byte_size(Value) =< ?MAXIMUM_DATE_BYTES ->
    try
        Tokens = re:split(
            Value,
            <<"[\\x09\\x20-\\x2f\\x3b-\\x40\\x5b-\\x60\\x7b-\\x7e]+">>,
            [{return, binary}, trim]
        ),
        case parse_tokens(Tokens, undefined, undefined, undefined, undefined) of
            {Hour, Minute, Second, Day, Month, Year0}
                when Hour =< 23, Minute =< 59, Second =< 59,
                     Day >= 1, Day =< 31 ->
                Year = normalize_year(Year0),
                case Year >= 1601 andalso
                     calendar:valid_date({Year, Month, Day}) of
                    true ->
                        Gregorian = calendar:datetime_to_gregorian_seconds(
                            {{Year, Month, Day}, {Hour, Minute, Second}}
                        ),
                        {ok, Gregorian - ?UNIX_EPOCH_GREGORIAN_SECONDS};
                    false -> {error, nil}
                end;
            _ -> {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end;
parse_cookie_date(_) ->
    {error, nil}.

parse_tokens([], {Hour, Minute, Second}, Day, Month, Year) ->
    {Hour, Minute, Second, Day, Month, Year};
parse_tokens([], _Time, _Day, _Month, _Year) ->
    incomplete;
parse_tokens([Token | Rest], Time0, Day0, Month0, Year0) ->
    case {Time0, parse_time(Token)} of
        {undefined, {ok, Time}} ->
            parse_tokens(Rest, Time, Day0, Month0, Year0);
        _ ->
            case {Day0, parse_day(Token)} of
                {undefined, {ok, Day}} ->
                    parse_tokens(Rest, Time0, Day, Month0, Year0);
                _ ->
                    case {Month0, parse_month(Token)} of
                        {undefined, {ok, Month}} ->
                            parse_tokens(Rest, Time0, Day0, Month, Year0);
                        _ ->
                            case {Year0, parse_year(Token)} of
                                {undefined, {ok, Year}} ->
                                    parse_tokens(
                                        Rest, Time0, Day0, Month0, Year
                                    );
                                _ ->
                                    parse_tokens(
                                        Rest, Time0, Day0, Month0, Year0
                                    )
                            end
                    end
            end
    end.

parse_time(Token) ->
    case re:run(
        Token,
        <<"^([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(?:[^0-9].*)?$">>,
        [{capture, [1, 2, 3], binary}]
    ) of
        {match, [Hour, Minute, Second]} ->
            {ok, {binary_to_integer(Hour), binary_to_integer(Minute),
                  binary_to_integer(Second)}};
        nomatch -> error
    end.

parse_day(Token) ->
    capture_integer(Token, <<"^([0-9]{1,2})(?:[^0-9].*)?$">>).

parse_year(Token) ->
    capture_integer(Token, <<"^([0-9]{2,4})(?:[^0-9].*)?$">>).

capture_integer(Token, Pattern) ->
    case re:run(Token, Pattern, [{capture, [1], binary}]) of
        {match, [Digits]} -> {ok, binary_to_integer(Digits)};
        nomatch -> error
    end.

parse_month(Token) ->
    case re:run(
        Token,
        <<"^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec).*$">>,
        [caseless, {capture, [1], binary}]
    ) of
        {match, [Month]} -> month_number(string:lowercase(Month));
        nomatch -> error
    end.

month_number(<<"jan">>) -> {ok, 1};
month_number(<<"feb">>) -> {ok, 2};
month_number(<<"mar">>) -> {ok, 3};
month_number(<<"apr">>) -> {ok, 4};
month_number(<<"may">>) -> {ok, 5};
month_number(<<"jun">>) -> {ok, 6};
month_number(<<"jul">>) -> {ok, 7};
month_number(<<"aug">>) -> {ok, 8};
month_number(<<"sep">>) -> {ok, 9};
month_number(<<"oct">>) -> {ok, 10};
month_number(<<"nov">>) -> {ok, 11};
month_number(<<"dec">>) -> {ok, 12}.

normalize_year(Year) when Year >= 70, Year =< 99 -> Year + 1900;
normalize_year(Year) when Year >= 0, Year =< 69 -> Year + 2000;
normalize_year(Year) -> Year.
