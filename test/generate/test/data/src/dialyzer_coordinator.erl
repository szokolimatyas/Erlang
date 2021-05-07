-file("dialyzer_coordinator.erl", 1).

-module(dialyzer_coordinator).

-export([parallel_job/4]).

-export([job_done/3]).

-export([sccs_to_pids/2, request_activation/1]).

-export([get_next_label/2]).

-export_type([coordinator/0, mode/0, init_data/0, result/0, job/0]).

-type(collector()::pid()).

-type(regulator()::pid()).

-type(scc_to_pid()::ets:tid()|unused).

-opaque(coordinator()::{collector(),regulator(),scc_to_pid()}).

-type(timing()::dialyzer_timing:timing_server()).

-type(scc()::[mfa_or_funlbl()]).

-type(mode()::typesig|dataflow|compile|warnings).

-type(compile_job()::file:filename()).

-type(typesig_job()::scc()).

-type(dataflow_job()::module()).

-type(warnings_job()::module()).

-type(job()::compile_job()|typesig_job()|dataflow_job()|warnings_job()).

-type(compile_init_data()::dialyzer_analysis_callgraph:compile_init_data()).

-type(typesig_init_data()::dialyzer_succ_typings:typesig_init_data()).

-type(dataflow_init_data()::dialyzer_succ_typings:dataflow_init_data()).

-type(warnings_init_data()::dialyzer_succ_typings:warnings_init_data()).

-type(compile_result()::dialyzer_analysis_callgraph:compile_result()).

-type(typesig_result()::[mfa_or_funlbl()]).

-type(dataflow_result()::[mfa_or_funlbl()]).

-type(warnings_result()::[dial_warning()]).

-type(init_data()::compile_init_data()|typesig_init_data()|dataflow_init_data()|warnings_init_data()).

-type(result()::compile_result()|typesig_result()|dataflow_result()|warnings_result()).

-type(job_result()::dialyzer_analysis_callgraph:one_file_mid_error()|dialyzer_analysis_callgraph:one_file_result_ok()|typesig_result()|dataflow_result()|warnings_result()).

-record(state,{mode::mode(),active = 0::integer(),result::result(),next_label = 0::integer(),jobs::[job()],job_fun::fun(),init_data::init_data(),regulator::regulator(),scc_to_pid::scc_to_pid()}).

-file("dialyzer.hrl", 1).

-type(dial_ret()::0|1|2).

-type(dial_warn_tag()::warn_return_no_exit|warn_return_only_exit|warn_not_called|warn_non_proper_list|warn_matching|warn_opaque|warn_fun_app|warn_failing_call|warn_bin_construction|warn_contract_types|warn_contract_syntax|warn_contract_not_equal|warn_contract_subtype|warn_contract_supertype|warn_callgraph|warn_umatched_return|warn_race_condition|warn_behaviour|warn_contract_range|warn_undefined_callbacks|warn_unknown|warn_map_construction).

-type(file_line()::{file:filename(),non_neg_integer()}).

-type(dial_warning()::{dial_warn_tag(),file_line(),{atom(),[term()]}}).

-type(m_or_mfa()::module()|mfa()).

-type(warning_info()::{file:filename(),non_neg_integer(),m_or_mfa()}).

-type(raw_warning()::{dial_warn_tag(),warning_info(),{atom(),[term()]}}).

-type(dial_error()::any()).

-type(anal_type()::succ_typings|plt_build).

-type(anal_type1()::anal_type()|plt_add|plt_check|plt_remove).

-type(contr_constr()::{subtype,erl_types:erl_type(),erl_types:erl_type()}).

-type(contract_pair()::{erl_types:erl_type(),[contr_constr()]}).

-type(dial_define()::{atom(),term()}).

-type(dial_option()::{atom(),term()}).

-type(dial_options()::[dial_option()]).

-type(fopt()::basename|fullpath).

-type(format()::formatted|raw).

-type(iopt()::boolean()).

-type(label()::non_neg_integer()).

-type(dial_warn_tags()::ordsets:ordset(dial_warn_tag())).

-type(rep_mode()::quiet|normal|verbose).

-type(start_from()::byte_code|src_code).

-type(mfa_or_funlbl()::label()|mfa()).

-type(solver()::v1|v2).

-type(doc_plt()::undefined|dialyzer_plt:plt()).

-record(analysis,{analysis_pid::pid()|undefined,type = succ_typings::anal_type(),defines = []::[dial_define()],doc_plt::doc_plt(),files = []::[file:filename()],include_dirs = []::[file:filename()],start_from = byte_code::start_from(),plt::dialyzer_plt:plt(),use_contracts = true::boolean(),race_detection = false::boolean(),behaviours_chk = false::boolean(),timing = false::boolean()|debug,timing_server = none::dialyzer_timing:timing_server(),callgraph_file = ""::file:filename(),solvers::[solver()]}).

-record(options,{files = []::[file:filename()],files_rec = []::[file:filename()],analysis_type = succ_typings::anal_type1(),timing = false::boolean()|debug,defines = []::[dial_define()],from = byte_code::start_from(),get_warnings = maybe::boolean()|maybe,init_plts = []::[file:filename()],include_dirs = []::[file:filename()],output_plt = none::none|file:filename(),legal_warnings = ordsets:new()::dial_warn_tags(),report_mode = normal::rep_mode(),erlang_mode = false::boolean(),use_contracts = true::boolean(),output_file = none::none|file:filename(),output_format = formatted::format(),filename_opt = basename::fopt(),indent_opt = true::iopt(),callgraph_file = ""::file:filename(),check_plt = true::boolean(),solvers = []::[solver()],native = maybe::boolean()|maybe,native_cache = true::boolean()}).

-record(contract,{contracts = []::[contract_pair()],args = []::[erl_types:erl_type()],forms = []::[{_,_}]}).

-file("dialyzer_coordinator.erl", 87).

-spec(parallel_job(compile,[compile_job()],compile_init_data(),timing()) -> {compile_result(),integer()};(typesig,[typesig_job()],typesig_init_data(),timing()) -> typesig_result();(dataflow,[dataflow_job()],dataflow_init_data(),timing()) -> dataflow_result();(warnings,[warnings_job()],warnings_init_data(),timing()) -> warnings_result()).

parallel_job(Mode,Jobs,InitData,Timing) ->
    State = spawn_jobs(Mode,Jobs,InitData,Timing),
    collect_result(State).

spawn_jobs(Mode,Jobs,InitData,Timing) ->
    Collector = self(),
    Regulator = spawn_regulator(),
    TypesigOrDataflow = Mode =:= typesig orelse Mode =:= dataflow,
    SCCtoPID = case TypesigOrDataflow of
        true->
            ets:new(scc_to_pid,[{read_concurrency,true}]);
        false->
            unused
    end,
    Coordinator = {Collector,Regulator,SCCtoPID},
    JobFun = fun (Job)->
        Pid = dialyzer_worker:launch(Mode,Job,InitData,Coordinator),
        case TypesigOrDataflow of
            true->
                true = ets:insert(SCCtoPID,{Job,Pid});
            false->
                true
        end end,
    JobCount = length(Jobs),
    NumberOfInitJobs = min(JobCount,20 * dialyzer_utils:parallelism()),
    {InitJobs,RestJobs} = lists:split(NumberOfInitJobs,Jobs),
    lists:foreach(JobFun,InitJobs),
    Unit = case Mode of
        typesig->
            "SCCs";
        _->
            "modules"
    end,
    dialyzer_timing:send_size_info(Timing,JobCount,Unit),
    InitResult = case Mode of
        compile->
            dialyzer_analysis_callgraph:compile_init_result();
        _->
            []
    end,
    #state{mode = Mode,active = JobCount,result = InitResult,next_label = 0,job_fun = JobFun,jobs = RestJobs,init_data = InitData,regulator = Regulator,scc_to_pid = SCCtoPID}.

collect_result(#state{mode = Mode,active = Active,result = Result,next_label = NextLabel,init_data = InitData,jobs = JobsLeft,job_fun = JobFun,regulator = Regulator,scc_to_pid = SCCtoPID} = State) ->
    receive {next_label_request,Estimation,Pid}->
        Pid ! {next_label_reply,NextLabel},
        collect_result(State#state{next_label = NextLabel + Estimation});
    {done,Job,Data}->
        NewResult = update_result(Mode,InitData,Job,Data,Result),
        TypesigOrDataflow = Mode =:= typesig orelse Mode =:= dataflow,
        case Active of
            1->
                kill_regulator(Regulator),
                case Mode of
                    compile->
                        {NewResult,NextLabel};
                    _
                        when TypesigOrDataflow->
                        ets:delete(SCCtoPID),
                        NewResult;
                    warnings->
                        NewResult
                end;
            N->
                case TypesigOrDataflow of
                    true->
                        true = ets:delete(SCCtoPID,Job);
                    false->
                        true
                end,
                NewJobsLeft = case JobsLeft of
                    []->
                        [];
                    [NewJob| JobsLeft1]->
                        JobFun(NewJob),
                        JobsLeft1
                end,
                NewState = State#state{result = NewResult,jobs = NewJobsLeft,active = N - 1},
                collect_result(NewState)
        end end.

update_result(Mode,InitData,Job,Data,Result) ->
    case Mode of
        compile->
            dialyzer_analysis_callgraph:add_to_result(Job,Data,Result,InitData);
        X
            when X =:= typesig;
            X =:= dataflow->
            dialyzer_succ_typings:lookup_names(Data,InitData) ++ Result;
        warnings->
            Data ++ Result
    end.

-spec(sccs_to_pids([scc()|module()],coordinator()) -> [dialyzer_worker:worker()]).

sccs_to_pids(SCCs,{_Collector,_Regulator,SCCtoPID}) ->
    Fold = fun (SCC,Pids)->
        try ets:lookup_element(SCCtoPID,SCC,2) of 
            Pid
                when is_pid(Pid)->
                [Pid| Pids]
            catch
                _:_->
                    Pids end end,
    lists:foldl(Fold,[],SCCs).

-spec(job_done(job(),job_result(),coordinator()) -> ok).

job_done(Job,Result,{Collector,Regulator,_SCCtoPID}) ->
    Regulator ! done,
    Collector ! {done,Job,Result},
    ok.

-spec(get_next_label(integer(),coordinator()) -> integer()).

get_next_label(EstimatedSize,{Collector,_Regulator,_SCCtoPID}) ->
    Collector ! {next_label_request,EstimatedSize,self()},
    receive {next_label_reply,NextLabel}->
        NextLabel end.

-spec(wait_activation() -> ok).

wait_activation() ->
    receive activate->
        ok end.

activate_pid(Pid) ->
    Pid ! activate.

-spec(request_activation(coordinator()) -> ok).

request_activation({_Collector,Regulator,_SCCtoPID}) ->
    Regulator ! {req,self()},
    wait_activation().

spawn_regulator() ->
    InitTickets = dialyzer_utils:parallelism(),
    spawn_link(fun ()->
        regulator_loop(InitTickets,queue:new()) end).

regulator_loop(Tickets,Queue) ->
    receive {req,Pid}->
        case Tickets of
            0->
                regulator_loop(0,queue:in(Pid,Queue));
            N->
                activate_pid(Pid),
                regulator_loop(N - 1,Queue)
        end;
    done->
        {Waiting,NewQueue} = queue:out(Queue),
        NewTickets = case Waiting of
            empty->
                Tickets + 1;
            {value,Pid}->
                activate_pid(Pid),
                Tickets
        end,
        regulator_loop(NewTickets,NewQueue);
    stop->
        ok end.

kill_regulator(Regulator) ->
    Regulator ! stop.