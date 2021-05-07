-file("ssh_tcpip_forward_client.erl", 1).

-module(ssh_tcpip_forward_client).

-behaviour(ssh_client_channel).

-record(state, {id,cm,fwd_socket}).

-export([init/1, handle_call/3, handle_cast/2, handle_msg/2, handle_ssh_msg/2, terminate/2, code_change/3]).

init([FwdSocket]) ->
    {ok,#state{fwd_socket = FwdSocket}}.

handle_msg({ssh_channel_up,ChannelId,ConnectionManager},State) ->
    {ok,State#state{id = ChannelId,cm = ConnectionManager}};
handle_msg({tcp,Sock,Data},#state{fwd_socket = Sock,cm = CM,id = ChId} = State) ->
    ssh_connection:send(CM,ChId,Data),
    inet:setopts(Sock,[{active,once}]),
    {ok,State};
handle_msg({tcp_closed,Sock},#state{fwd_socket = Sock,cm = CM,id = ChId} = State) ->
    ssh_connection:send_eof(CM,ChId),
    {stop,ChId,State#state{fwd_socket = undefined}}.

handle_ssh_msg({ssh_cm,_CM,{data,_ChannelId,_Type,Data}},#state{fwd_socket = Sock} = State) ->
    gen_tcp:send(Sock,Data),
    {ok,State};
handle_ssh_msg({ssh_cm,_CM,{eof,ChId}},State) ->
    {stop,ChId,State};
handle_ssh_msg({ssh_cm,_CM,{signal,_,_}},State) ->
    {ok,State};
handle_ssh_msg({ssh_cm,_CM,{exit_signal,ChId,_,_Error,_}},State) ->
    {stop,ChId,State};
handle_ssh_msg({ssh_cm,_,{exit_status,ChId,_Status}},State) ->
    {stop,ChId,State}.

terminate(_Reason,#state{fwd_socket = Sock}) ->
    gen_tcp:close(Sock),
    ok.

handle_call(Req,_,S) ->
    {reply,{unknown,Req},S}.

handle_cast(_,S) ->
    {noreply,S}.

code_change(_,S,_) ->
    {ok,S}.