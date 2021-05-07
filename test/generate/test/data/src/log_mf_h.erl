-file("log_mf_h.erl", 1).

-module(log_mf_h).

-behaviour(gen_event).

-export([init/3, init/4]).

-export([init/1, handle_event/2, handle_info/2, terminate/2]).

-export([handle_call/2, code_change/3]).

-export_type([args/0]).

-type(b()::non_neg_integer()).

-type(f()::1..255).

-type(pred()::fun((term()) -> boolean())).

-record(state,{dir::file:filename(),maxB::b(),maxF::f(),curB::b(),curF::f(),cur_fd::file:fd(),index = [],pred::pred()}).

-opaque(args()::{file:filename(),b(),f(),pred()}).

-spec(init(Dir,MaxBytes,MaxFiles) -> Args when Dir::file:filename(),MaxBytes::non_neg_integer(),MaxFiles::1..255,Args::args()).

init(Dir,MaxB,MaxF) ->
    init(Dir,MaxB,MaxF,fun (_)->
        true end).

-spec(init(Dir,MaxBytes,MaxFiles,Pred) -> Args when Dir::file:filename(),MaxBytes::non_neg_integer(),MaxFiles::1..255,Pred::fun((Event::term()) -> boolean()),Args::args()).

init(Dir,MaxB,MaxF,Pred) ->
    {Dir,MaxB,MaxF,Pred}.

-spec(init({file:filename(),non_neg_integer(),f(),pred()}) -> {ok,#state{}}|{error,term()}).

init({Dir,MaxB,MaxF,Pred})
    when is_integer(MaxF),
    MaxF > 0,
    MaxF < 256->
    First = case read_index_file(Dir) of
        {ok,LastWritten}->
            inc(LastWritten,MaxF);
        _->
            1
    end,
    case  catch file_open(Dir,First) of
        {ok,Fd}->
            {ok,#state{dir = Dir,maxB = MaxB,maxF = MaxF,pred = Pred,curF = First,cur_fd = Fd,curB = 0}};
        Error->
            Error
    end.

-spec(handle_event(term(),#state{}) -> {ok,#state{}}).

handle_event(Event,State) ->
    #state{curB = CurB,maxB = MaxB,curF = CurF,maxF = MaxF,dir = Dir,cur_fd = CurFd,pred = Pred} = State,
    case  catch Pred(Event) of
        true->
            Bin = term_to_binary(tag_event(Event)),
            Size = byte_size(Bin),
            NewState = if CurB + Size < MaxB ->
                State;true ->
                ok = file:close(CurFd),
                NewF = inc(CurF,MaxF),
                {ok,NewFd} = file_open(Dir,NewF),
                State#state{cur_fd = NewFd,curF = NewF,curB = 0} end,
            [Hi, Lo] = put_int16(Size),
            case file:write(NewState#state.cur_fd,[Hi, Lo, Bin]) of
                ok->
                    ok;
                {error,Reason}->
                    exit({file_exit,Reason})
            end,
            {ok,NewState#state{curB = NewState#state.curB + Size + 2}};
        _->
            {ok,State}
    end.

-spec(handle_info(term(),#state{}) -> {ok,#state{}}).

handle_info({emulator,GL,Chars},State) ->
    handle_event({emulator,GL,Chars},State);
handle_info(_,State) ->
    {ok,State}.

-spec(terminate(term(),#state{}) -> #state{}).

terminate(_,State) ->
    ok = file:close(State#state.cur_fd),
    State.

-spec(handle_call(null,#state{}) -> {ok,null,#state{}}).

handle_call(null,State) ->
    {ok,null,State}.

-spec(code_change(term(),#state{},term()) -> {ok,#state{}}).

code_change(_OldVsn,State,_Extra) ->
    {ok,State}.

file_open(Dir,FileNo) ->
    case file:open(Dir ++ [$/| integer_to_list(FileNo)],[raw, write]) of
        {ok,Fd}->
            write_index_file(Dir,FileNo),
            {ok,Fd};
        _->
            exit(file_open)
    end.

put_int16(I) ->
    [I band 65280 bsr 8, I band 255].

tag_event(Event) ->
    {erlang:localtime(),Event}.

read_index_file(Dir) ->
    case file:open(Dir ++ "/index",[raw, read]) of
        {ok,Fd}->
            Res = case  catch file:read(Fd,1) of
                {ok,[Index]}->
                    {ok,Index};
                _->
                    error
            end,
            ok = file:close(Fd),
            Res;
        _->
            error
    end.

write_index_file(Dir,Index) ->
    File = Dir ++ "/index",
    TmpFile = File ++ ".tmp",
    case file:open(TmpFile,[raw, write]) of
        {ok,Fd}->
            ok = file:write(Fd,[Index]),
            ok = file:close(Fd),
            ok = file:rename(TmpFile,File),
            ok;
        _->
            exit(write_index_file)
    end.

inc(N,Max) ->
    if N < Max ->
        N + 1;true ->
        1 end.