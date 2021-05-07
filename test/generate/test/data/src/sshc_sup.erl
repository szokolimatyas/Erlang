-file("sshc_sup.erl", 1).

-module(sshc_sup).

-behaviour(supervisor).

-export([start_link/0, start_child/4, start_system_subsystem/4, stop_child/1, stop_system/1]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local,sshc_sup},sshc_sup,[]).

start_child(Address,Port,Profile,Options) ->
    case ssh_system_sup:system_supervisor(Address,Port,Profile) of
        undefined->
            Spec = child_spec(Address,Port,Profile,Options),
            supervisor:start_child(sshc_sup,Spec);
        Pid->
            {ok,Pid}
    end.

start_system_subsystem(Host,Port,Profile,Options) ->
    ssh_controller:start_system_subsystem(client_controller,sshc_sup,Host,Port,Profile,Options,child_spec(Host,Port,Profile,Options)).

stop_child(ChildId)
    when is_tuple(ChildId)->
    supervisor:terminate_child(sshc_sup,ChildId);
stop_child(ChildPid)
    when is_pid(ChildPid)->
    stop_child(system_name(ChildPid)).

stop_system(SysSup) ->
    ssh_controller:stop_system(client_controller,SysSup).

init(_) ->
    SupFlags = #{strategy=>one_for_one,intensity=>0,period=>3600},
    ChildSpecs = [#{id=>client_controller,start=>{ssh_controller,start_link,[client, client_controller]},restart=>permanent,type=>worker}],
    {ok,{SupFlags,ChildSpecs}}.

child_spec(Address,Port,Profile,Options) ->
    #{id=>id(Address,Port,Profile),start=>{ssh_system_sup,start_link,[client, Address, Port, Profile, Options]},restart=>temporary,type=>supervisor}.

id(Address,Port,Profile) ->
    {client,ssh_system_sup,Address,Port,Profile}.

system_name(SysSup) ->
    case lists:keyfind(SysSup,2,supervisor:which_children(sshc_sup)) of
        {Name,SysSup,_,_}->
            Name;
        false->
            undefind
    end.