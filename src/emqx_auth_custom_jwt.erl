%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqx_auth_custom_jwt).

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").

-logger_header("[JWT]").

-export([ register_metrics/0
        , check/3
        , description/0
        ]).

-record(auth_metrics, {
        success = 'client.auth.success',
        failure = 'client.auth.failure',
        ignore = 'client.auth.ignore'
    }).

-define(METRICS(Type), tl(tuple_to_list(#Type{}))).
-define(METRICS(Type, K), #Type{}#Type.K).

-define(AUTH_METRICS, ?METRICS(auth_metrics)).
-define(AUTH_METRICS(K), ?METRICS(auth_metrics, K)).

-spec(register_metrics() -> ok).
register_metrics() ->
    lists:foreach(fun emqx_metrics:ensure/1, ?AUTH_METRICS).

%%--------------------------------------------------------------------
%% Authentication callbacks
%%--------------------------------------------------------------------

check(ClientInfo, AuthResult, Env = #{from := From, checklists := Checklists}) ->
    case maps:find(From, ClientInfo) of
        error ->
            ok = emqx_metrics:inc(?AUTH_METRICS(ignore)),
            {ok, AuthResult#{auth_result => token_undefined, anonymous => false}};
        {ok, Token} ->            
            try jwerl:header(Token) of
                Headers ->
                    case verify_token(Headers, Token, Env) of
                        {ok, Claims} ->
                            {stop, maps:merge(AuthResult, verify_claims(Checklists, Claims, ClientInfo))};
                        {error, Reason} ->
                            ok = emqx_metrics:inc(?AUTH_METRICS(failure)),
                            {stop, AuthResult#{auth_result => Reason, anonymous => false}}
                    end
            catch
                _Error:Reason ->
                    ?LOG(error, "Check token error: ~p", [Reason]),
                    emqx_metrics:inc(?AUTH_METRICS(ignore))
            end
    end.

description() -> "Authentication with JWT".

%%--------------------------------------------------------------------
%% Verify Token
%%--------------------------------------------------------------------

verify_token(#{alg := <<"RS", _/binary>>}, _Token, #{authority := undefined}) ->
    {error, rsa_pubkey_undefined};

verify_token(#{kid := KId}, Token, #{authority := Authority}) ->
    application:ensure_all_started(jwk),
    PubKey = get_authority_pub_key(Authority),
    case jwk:decode(KId,PubKey) of 
        {ok,Jwk} ->
            verify_token2(Token,Jwk);
        {error, Reason} ->
            {error, Reason}
    end.

verify_token2(Token, Key) ->
    application:ensure_all_started(jwt),
    try jwt:decode(Token, Key) of
        {ok, Claims}  ->
            {ok, Claims};
        {error, Reason} ->
            {error, Reason}
    catch
        _Error:Reason ->
            {error, Reason}
    end.




decode_algo(<<"RS256">>) -> rs256;
decode_algo(<<"RS384">>) -> rs384;
decode_algo(<<"RS512">>) -> rs512;
decode_algo(Alg) -> throw({error, {unsupported_algorithm, Alg}}).

%%--------------------------------------------------------------------
%% Verify Claims
%%--------------------------------------------------------------------

verify_claims(Checklists, Claims, ClientInfo) ->
    case do_verify_claims(feedvar(Checklists, ClientInfo), Claims) of
        {error, Reason} ->
            ok = emqx_metrics:inc(?AUTH_METRICS(failure)),
            #{auth_result => Reason, anonymous => false};
        ok ->
            ok = emqx_metrics:inc(?AUTH_METRICS(success)),
            #{auth_result => success, anonymous => false, jwt_claims => Claims}
    end.

do_verify_claims([], _Claims) ->
    ok;
do_verify_claims([{Key, Expected} | L], Claims) ->
    case maps:get(Key, Claims, undefined) =:= Expected of
        true -> do_verify_claims(L, Claims);
        false -> {error, {verify_claim_failed, Key}}
    end.

feedvar(Checklists, #{username := Username, clientid := ClientId}) ->
    lists:map(fun({K, <<"%u">>}) -> {K, Username};
                 ({K, <<"%c">>}) -> {K, ClientId};
                 ({K, Expected}) -> {K, Expected}
              end, Checklists).



%%--------------------------------------------------------------------
%% Get Authority document
%%--------------------------------------------------------------------


get_authority_pub_key(Authority) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    ConfigurationUrl =
        Authority++".well-known/openid-configuration",
    {ok, { {_, 200, _}, _, ConfigurationJson}} =
        httpc:request(ConfigurationUrl),
    Configuration = jiffy:decode(ConfigurationJson, [return_maps]),
    #{<<"jwks_uri">> := JwksUri} = Configuration,
    {ok, { {_, 200, _}, _, JwksJson}} = httpc:request(binary_to_list(JwksUri)),
    jsx:decode(list_to_binary(JwksJson),[return_maps]).

