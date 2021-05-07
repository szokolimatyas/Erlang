-file("erl_tar.erl", 1).

-module(erl_tar).

-export([init/3, create/2, create/3, extract/1, extract/2, table/1, table/2, t/1, tt/1, open/2, close/1, add/3, add/4, format_error/1]).

-file("/usr/lib/erlang/lib/kernel-7.2/include/file.hrl", 1).

-record(file_info,{size::non_neg_integer()|undefined,type::device|directory|other|regular|symlink|undefined,access::read|write|read_write|none|undefined,atime::file:date_time()|non_neg_integer()|undefined,mtime::file:date_time()|non_neg_integer()|undefined,ctime::file:date_time()|non_neg_integer()|undefined,mode::non_neg_integer()|undefined,links::non_neg_integer()|undefined,major_device::non_neg_integer()|undefined,minor_device::non_neg_integer()|undefined,inode::non_neg_integer()|undefined,uid::non_neg_integer()|undefined,gid::non_neg_integer()|undefined}).

-record(file_descriptor,{module::module(),data::term()}).

-file("erl_tar.erl", 41).

-file("erl_tar.hrl", 1).

-record(add_opts, {read_info,chunk_size = 0,verbose = false,atime = undefined,mtime = undefined,ctime = undefined,uid = 0,gid = 0}).

-type(add_opts()::#add_opts{}).

-record(read_opts,{cwd::string(),keep_old_files = false::boolean(),files = all,output = file::file|memory,open_mode = [],verbose = false::boolean()}).

-type(read_opts()::#read_opts{}).

-type(add_opt()::dereference|verbose|{chunks,pos_integer()}|{atime,non_neg_integer()}|{mtime,non_neg_integer()}|{ctime,non_neg_integer()}|{uid,non_neg_integer()}|{gid,non_neg_integer()}).

-type(name_in_archive()::string()).

-type(extract_opt()::{cwd,string()}|{files,[name_in_archive()]}|compressed|cooked|memory|keep_old_files|verbose).

-type(create_opt()::compressed|cooked|dereference|verbose).

-type(filelist()::[file:filename()|{name_in_archive(),file:filename_all()}]).

-type(tar_time()::non_neg_integer()).

-record(tar_header,{name = ""::name_in_archive(),mode = 33188::non_neg_integer(),uid = 0::non_neg_integer(),gid = 0::non_neg_integer(),size = 0::non_neg_integer(),mtime::tar_time(),typeflag::char(),linkname = ""::name_in_archive(),uname = ""::string(),gname = ""::string(),devmajor = 0::non_neg_integer(),devminor = 0::non_neg_integer(),atime::tar_time(),ctime::tar_time()}).

-type(tar_header()::#tar_header{}).

-record(sparse_entry,{offset = 0::non_neg_integer(),num_bytes = 0::non_neg_integer()}).

-type(sparse_entry()::#sparse_entry{}).

-record(sparse_array,{entries = []::[sparse_entry()],is_extended = false::boolean(),max_entries = 0::non_neg_integer()}).

-type(sparse_array()::#sparse_array{}).

-record(header_v7,{name::binary(),mode::binary(),uid::binary(),gid::binary(),size::binary(),mtime::binary(),checksum::binary(),typeflag::byte(),linkname::binary()}).

-type(header_v7()::#header_v7{}).

-record(header_gnu,{header_v7::header_v7(),magic::binary(),version::binary(),uname::binary(),gname::binary(),devmajor::binary(),devminor::binary(),atime::binary(),ctime::binary(),sparse::sparse_array(),real_size::binary()}).

-type(header_gnu()::#header_gnu{}).

-record(header_star,{header_v7::header_v7(),magic::binary(),version::binary(),uname::binary(),gname::binary(),devmajor::binary(),devminor::binary(),prefix::binary(),atime::binary(),ctime::binary(),trailer::binary()}).

-type(header_star()::#header_star{}).

-record(header_ustar,{header_v7::header_v7(),magic::binary(),version::binary(),uname::binary(),gname::binary(),devmajor::binary(),devminor::binary(),prefix::binary()}).

-type(header_ustar()::#header_ustar{}).

-type(header_fields()::header_v7()|header_gnu()|header_star()|header_ustar()).

-record(reader,{handle::user_data(),access::read|write|ram,pos = 0::non_neg_integer(),func::file_op()}).

-opaque(tar_descriptor()::#reader{}).

-export_type([tar_descriptor/0]).

-record(reg_file_reader,{handle::tar_descriptor(),num_bytes = 0,
pos = 0,
size = 0}).

-type(reg_file_reader()::#reg_file_reader{}).

-record(sparse_file_reader,{handle::tar_descriptor(),num_bytes = 0,
pos = 0,
size = 0,
sparse_map = #sparse_array{}}).

-type(sparse_file_reader()::#sparse_file_reader{}).

-type(descriptor_type()::tar_descriptor()|reg_file_reader()|sparse_file_reader()).

-type(user_data()::term()).

-type(file_op()::fun((write|close|read2|position,{user_data(),iodata()}|user_data()|{user_data(),non_neg_integer()}|{user_data(),non_neg_integer()}) -> ok|eof|{ok,string()|binary()}|{ok,non_neg_integer()}|{error,term()})).

-file("erl_tar.erl", 42).

-spec(format_error(term()) -> string()).

format_error(invalid_tar_checksum) ->
    "Checksum failed";
format_error(bad_header) ->
    "Unrecognized tar header format";
format_error({bad_header,Reason}) ->
    lists:flatten(io_lib:format("Unrecognized tar header format: ~p",[Reason]));
format_error({invalid_header,negative_size}) ->
    "Invalid header: negative size";
format_error(invalid_sparse_header_size) ->
    "Invalid sparse header: negative size";
format_error(invalid_sparse_map_entry) ->
    "Invalid sparse map entry";
format_error({invalid_sparse_map_entry,Reason}) ->
    lists:flatten(io_lib:format("Invalid sparse map entry: ~p",[Reason]));
format_error(invalid_end_of_archive) ->
    "Invalid end of archive";
format_error(eof) ->
    "Unexpected end of file";
format_error(integer_overflow) ->
    "Failed to parse numeric: integer overflow";
format_error({misaligned_read,Pos}) ->
    lists:flatten(io_lib:format("Read a block which was misaligned: blo" "ck_size=~p pos=~p",[512, Pos]));
format_error(invalid_gnu_1_0_sparsemap) ->
    "Invalid GNU sparse map (version 1.0)";
format_error({invalid_gnu_0_1_sparsemap,Format}) ->
    lists:flatten(io_lib:format("Invalid GNU sparse map (version ~s)",[Format]));
format_error(unsafe_path) ->
    "The path points above the current working directory";
format_error({Name,Reason}) ->
    lists:flatten(io_lib:format("~ts: ~ts",[Name, format_error(Reason)]));
format_error(Atom)
    when is_atom(Atom)->
    file:format_error(Atom);
format_error(Term) ->
    lists:flatten(io_lib:format("~tp",[Term])).

-spec(init(UserData::user_data(),write|read,file_op()) -> {ok,tar_descriptor()}|{error,badarg}).

init(UserData,AccessMode,Fun)
    when is_function(Fun,2)->
    Reader = #reader{handle = UserData,access = AccessMode,func = Fun},
    {ok,Pos,Reader2} = do_position(Reader,{cur,0}),
    {ok,Reader2#reader{pos = Pos}};
init(_UserData,_AccessMode,_Fun) ->
    {error,badarg}.

-spec(extract(Open::open_type()) -> ok|{error,term()}).

extract(Name) ->
    extract(Name,[]).

-spec(extract(Open::open_type(),[extract_opt()]) -> {ok,[{string(),binary()}]}|{error,term()}|ok).

extract({binary,Bin},Opts)
    when is_list(Opts)->
    do_extract({binary,Bin},Opts);
extract({file,Fd},Opts)
    when is_list(Opts)->
    do_extract({file,Fd},Opts);
extract(#reader{} = Reader,Opts)
    when is_list(Opts)->
    do_extract(Reader,Opts);
extract(Name,Opts)
    when is_list(Name);
    is_binary(Name),
    is_list(Opts)->
    do_extract(Name,Opts).

do_extract(Handle,Opts)
    when is_list(Opts)->
    Opts2 = extract_opts(Opts),
    Acc = if Opts2#read_opts.output =:= memory ->
        [];true ->
        ok end,
    foldl_read(Handle,fun extract1/4,Acc,Opts2).

extract1(eof,Reader,_,Acc)
    when is_list(Acc)->
    {ok,{ok,lists:reverse(Acc)},Reader};
extract1(eof,Reader,_,leading_slash) ->
    error_logger:info_msg("erl_tar: removed leading '/' from member nam" "es\n"),
    {ok,ok,Reader};
extract1(eof,Reader,_,Acc) ->
    {ok,Acc,Reader};
extract1(#tar_header{name = Name,size = Size} = Header,Reader0,Opts,Acc0) ->
    case check_extract(Name,Opts) of
        true->
            case do_read(Reader0,Size) of
                {ok,Bin,Reader1}->
                    Acc = extract2(Header,Bin,Opts,Acc0),
                    {ok,Acc,Reader1};
                {error,_} = Err->
                    throw(Err)
            end;
        false->
            {ok,Acc0,skip_file(Reader0)}
    end.

extract2(Header,Bin,Opts,Acc) ->
    case write_extracted_element(Header,Bin,Opts) of
        ok->
            case Header of
                #tar_header{name = "/" ++ _}->
                    leading_slash;
                #tar_header{}->
                    Acc
            end;
        {ok,NameBin}
            when is_list(Acc)->
            [NameBin| Acc];
        {error,_} = Err->
            throw(Err)
    end.

check_extract(_,#read_opts{files = all}) ->
    true;
check_extract(Name,#read_opts{files = Files}) ->
    ordsets:is_element(Name,Files).

-type(typeflag()::regular|link|symlink|char|block|directory|fifo|reserved|unknown).

-type(mode()::non_neg_integer()).

-type(uid()::non_neg_integer()).

-type(gid()::non_neg_integer()).

-type(tar_entry()::{Name::name_in_archive(),Type::typeflag(),Size::non_neg_integer(),MTime::tar_time(),Mode::mode(),Uid::uid(),Gid::gid()}).

-spec(table(Open::open_type()) -> {ok,[name_in_archive()]}|{error,term()}).

table(Name) ->
    table(Name,[]).

-spec(table(Open::open_type(),[compressed|verbose|cooked]) -> {ok,[name_in_archive()|tar_entry()]}|{error,term()}).

table(Name,Opts)
    when is_list(Opts)->
    foldl_read(Name,fun table1/4,[],table_opts(Opts)).

table1(eof,Reader,_,Result) ->
    {ok,{ok,lists:reverse(Result)},Reader};
table1(#tar_header{} = Header,Reader,#read_opts{verbose = Verbose},Result) ->
    Attrs = table1_attrs(Header,Verbose),
    Reader2 = skip_file(Reader),
    {ok,[Attrs| Result],Reader2}.

table1_attrs(#tar_header{typeflag = Typeflag,mode = Mode} = Header,true) ->
    Type = typeflag(Typeflag),
    Name = Header#tar_header.name,
    Mtime = Header#tar_header.mtime,
    Uid = Header#tar_header.uid,
    Gid = Header#tar_header.gid,
    Size = Header#tar_header.size,
    {Name,Type,Size,Mtime,Mode,Uid,Gid};
table1_attrs(#tar_header{name = Name},_Verbose) ->
    Name.

typeflag($0) ->
    regular;
typeflag(0) ->
    regular;
typeflag($S) ->
    regular;
typeflag($7) ->
    regular;
typeflag($1) ->
    link;
typeflag($2) ->
    symlink;
typeflag($3) ->
    char;
typeflag($4) ->
    block;
typeflag($5) ->
    directory;
typeflag($6) ->
    fifo;
typeflag(_) ->
    unknown.

-spec(t(file:filename()) -> ok|{error,term()}).

t(Name)
    when is_list(Name);
    is_binary(Name)->
    case table(Name) of
        {ok,List}->
            lists:foreach(fun (N)->
                ok = io:format("~ts\n",[N]) end,List);
        Error->
            Error
    end.

-spec(tt(open_type()) -> ok|{error,term()}).

tt(Name) ->
    case table(Name,[verbose]) of
        {ok,List}->
            lists:foreach(fun print_header/1,List);
        Error->
            Error
    end.

-spec(print_header(tar_entry()) -> ok).

print_header({Name,Type,Size,Mtime,Mode,Uid,Gid}) ->
    io:format("~s~s ~4w/~-4w ~7w ~s ~s\n",[type_to_string(Type), mode_to_string(Mode), Uid, Gid, Size, time_to_string(Mtime), Name]).

type_to_string(regular) ->
    "-";
type_to_string(directory) ->
    "d";
type_to_string(link) ->
    "l";
type_to_string(symlink) ->
    "s";
type_to_string(char) ->
    "c";
type_to_string(block) ->
    "b";
type_to_string(fifo) ->
    "f";
type_to_string(unknown) ->
    "?".

mode_to_string(Mode) ->
    mode_to_string(Mode,"xwrxwrxwr",[]).

mode_to_string(Mode,[C| T],Acc)
    when Mode band 1 =:= 1->
    mode_to_string(Mode bsr 1,T,[C| Acc]);
mode_to_string(Mode,[_| T],Acc) ->
    mode_to_string(Mode bsr 1,T,[$-| Acc]);
mode_to_string(_,[],Acc) ->
    Acc.

time_to_string(Secs0) ->
    Epoch = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    Secs = Epoch + Secs0,
    DateTime0 = calendar:gregorian_seconds_to_datetime(Secs),
    DateTime = calendar:universal_time_to_local_time(DateTime0),
    {{Y,Mon,Day},{H,Min,_}} = DateTime,
    io_lib:format("~s ~2w ~s:~s ~w",[month(Mon), Day, two_d(H), two_d(Min), Y]).

two_d(N) ->
    tl(integer_to_list(N + 100)).

month(1) ->
    "Jan";
month(2) ->
    "Feb";
month(3) ->
    "Mar";
month(4) ->
    "Apr";
month(5) ->
    "May";
month(6) ->
    "Jun";
month(7) ->
    "Jul";
month(8) ->
    "Aug";
month(9) ->
    "Sep";
month(10) ->
    "Oct";
month(11) ->
    "Nov";
month(12) ->
    "Dec".

-type(open_type()::file:filename_all()|{binary,binary()}|{file,file:io_device()}).

-spec(open(Open::open_type(),[write|compressed|cooked]) -> {ok,tar_descriptor()}|{error,term()}).

open({binary,Bin},Mode)
    when is_binary(Bin)->
    do_open({binary,Bin},Mode);
open({file,Fd},Mode) ->
    do_open({file,Fd},Mode);
open(Name,Mode)
    when is_list(Name);
    is_binary(Name)->
    do_open(Name,Mode).

do_open(Name,Mode)
    when is_list(Mode)->
    case open_mode(Mode) of
        {ok,Access,Raw,Opts}->
            open1(Name,Access,Raw,Opts);
        {error,Reason}->
            {error,{Name,Reason}}
    end.

open1({binary,Bin} = Handle,read,_Raw,Opts)
    when is_binary(Bin)->
    case file:open(Bin,[ram, binary, read]) of
        {ok,File}->
            _ = [(ram_file:uncompress(File)) || lists:member(compressed,Opts)],
            {ok,#reader{handle = File,access = read,func = fun file_op/2}};
        {error,Reason}->
            {error,{Handle,Reason}}
    end;
open1({file,Fd} = Handle,read,[raw],Opts) ->
    case  not lists:member(compressed,Opts) of
        true->
            Reader = #reader{handle = Fd,access = read,func = fun file_op/2},
            case do_position(Reader,{cur,0}) of
                {ok,Pos,Reader2}->
                    {ok,Reader2#reader{pos = Pos}};
                {error,Reason}->
                    {error,{Handle,Reason}}
            end;
        false->
            {error,{Handle,{incompatible_option,compressed}}}
    end;
open1({file,_Fd} = Handle,read,[],_Opts) ->
    {error,{Handle,{incompatible_option,cooked}}};
open1(Name,Access,Raw,Opts)
    when is_list(Name) or is_binary(Name)->
    case file:open(Name,Raw ++ [binary, Access| Opts]) of
        {ok,File}->
            {ok,#reader{handle = File,access = Access,func = fun file_op/2}};
        {error,Reason}->
            {error,{Name,Reason}}
    end.

open_mode(Mode) ->
    open_mode(Mode,false,[raw],[]).

open_mode(read,_,Raw,_) ->
    {ok,read,Raw,[]};
open_mode(write,_,Raw,_) ->
    {ok,write,Raw,[]};
open_mode([read| Rest],false,Raw,Opts) ->
    open_mode(Rest,read,Raw,Opts);
open_mode([write| Rest],false,Raw,Opts) ->
    open_mode(Rest,write,Raw,Opts);
open_mode([compressed| Rest],Access,Raw,Opts) ->
    open_mode(Rest,Access,Raw,[compressed, read_ahead| Opts]);
open_mode([cooked| Rest],Access,_Raw,Opts) ->
    open_mode(Rest,Access,[],Opts);
open_mode([],Access,Raw,Opts) ->
    {ok,Access,Raw,Opts};
open_mode(_,_,_,_) ->
    {error,einval}.

file_op(write,{Fd,Data}) ->
    file:write(Fd,Data);
file_op(position,{Fd,Pos}) ->
    file:position(Fd,Pos);
file_op(read2,{Fd,Size}) ->
    file:read(Fd,Size);
file_op(close,Fd) ->
    file:close(Fd).

-spec(close(TarDescriptor::tar_descriptor()) -> ok|{error,term()}).

close(#reader{access = read} = Reader) ->
    ok = do_close(Reader);
close(#reader{access = write} = Reader) ->
    {ok,Reader2} = pad_file(Reader),
    ok = do_close(Reader2),
    ok;
close(_) ->
    {error,einval}.

pad_file(#reader{pos = Pos} = Reader) ->
    PadCurrent = skip_padding(Pos + 512),
    Padding = <<0:PadCurrent/unit:8>>,
    do_write(Reader,[Padding, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>]).

-spec(create(file:filename_all(),filelist()) -> ok|{error,{string(),term()}}).

create(Name,FileList)
    when is_list(Name);
    is_binary(Name)->
    create(Name,FileList,[]).

-spec(create(file:filename_all(),filelist(),[create_opt()]) -> ok|{error,term()}|{error,{string(),term()}}).

create(Name,FileList,Options)
    when is_list(Name);
    is_binary(Name)->
    Mode = lists:filter(fun (X)->
        (X =:= compressed) or (X =:= cooked) end,Options),
    case open(Name,[write| Mode]) of
        {ok,TarFile}->
            do_create(TarFile,FileList,Options);
        {error,_} = Err->
            Err
    end.

do_create(TarFile,[],_Opts) ->
    close(TarFile);
do_create(TarFile,[{NameInArchive,NameOrBin}| Rest],Opts) ->
    case add(TarFile,NameOrBin,NameInArchive,Opts) of
        ok->
            do_create(TarFile,Rest,Opts);
        {error,_} = Err->
            _ = close(TarFile),
            Err
    end;
do_create(TarFile,[Name| Rest],Opts) ->
    case add(TarFile,Name,Name,Opts) of
        ok->
            do_create(TarFile,Rest,Opts);
        {error,_} = Err->
            _ = close(TarFile),
            Err
    end.

-type(add_type()::name_in_archive()|{name_in_archive(),file:filename_all()}).

-spec(add(TarDescriptor,AddType,Options) -> ok|{error,term()} when TarDescriptor::tar_descriptor(),AddType::add_type(),Options::[add_opt()]).

add(Reader,{NameInArchive,Name},Opts)
    when is_list(NameInArchive),
    is_list(Name)->
    do_add(Reader,Name,NameInArchive,Opts);
add(Reader,{NameInArchive,Bin},Opts)
    when is_list(NameInArchive),
    is_binary(Bin)->
    do_add(Reader,Bin,NameInArchive,Opts);
add(Reader,Name,Opts)
    when is_list(Name)->
    do_add(Reader,Name,Name,Opts).

-spec(add(TarDescriptor,Filename,NameInArchive,Options) -> ok|{error,term()} when TarDescriptor::tar_descriptor(),Filename::file:filename_all(),NameInArchive::name_in_archive(),Options::[add_opt()]).

add(Reader,NameOrBin,NameInArchive,Options)
    when is_list(NameOrBin);
    is_binary(NameOrBin),
    is_list(NameInArchive),
    is_list(Options)->
    do_add(Reader,NameOrBin,NameInArchive,Options).

do_add(#reader{access = write} = Reader,Name,NameInArchive,Options)
    when is_list(NameInArchive),
    is_list(Options)->
    RF = apply_file_info_opts_fun(Options,read_link_info),
    Opts = #add_opts{read_info = RF},
    add1(Reader,Name,NameInArchive,add_opts(Options,Options,Opts));
do_add(#reader{access = read},_,_,_) ->
    {error,eacces};
do_add(Reader,_,_,_) ->
    {error,{badarg,Reader}}.

add_opts([dereference| T],AllOptions,Opts) ->
    RF = apply_file_info_opts_fun(AllOptions,read_file_info),
    add_opts(T,AllOptions,Opts#add_opts{read_info = RF});
add_opts([verbose| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{verbose = true});
add_opts([{chunks,N}| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{chunk_size = N});
add_opts([{atime,Value}| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{atime = Value});
add_opts([{mtime,Value}| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{mtime = Value});
add_opts([{ctime,Value}| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{ctime = Value});
add_opts([{uid,Value}| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{uid = Value});
add_opts([{gid,Value}| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts#add_opts{gid = Value});
add_opts([_| T],AllOptions,Opts) ->
    add_opts(T,AllOptions,Opts);
add_opts([],_AllOptions,Opts) ->
    Opts.

apply_file_info_opts(Opts,{ok,FileInfo}) ->
    {ok,do_apply_file_info_opts(Opts,FileInfo)};
apply_file_info_opts(_Opts,Other) ->
    Other.

do_apply_file_info_opts([{atime,Value}| T],FileInfo) ->
    do_apply_file_info_opts(T,FileInfo#file_info{atime = Value});
do_apply_file_info_opts([{mtime,Value}| T],FileInfo) ->
    do_apply_file_info_opts(T,FileInfo#file_info{mtime = Value});
do_apply_file_info_opts([{ctime,Value}| T],FileInfo) ->
    do_apply_file_info_opts(T,FileInfo#file_info{ctime = Value});
do_apply_file_info_opts([{uid,Value}| T],FileInfo) ->
    do_apply_file_info_opts(T,FileInfo#file_info{uid = Value});
do_apply_file_info_opts([{gid,Value}| T],FileInfo) ->
    do_apply_file_info_opts(T,FileInfo#file_info{gid = Value});
do_apply_file_info_opts([_| T],FileInfo) ->
    do_apply_file_info_opts(T,FileInfo);
do_apply_file_info_opts([],FileInfo) ->
    FileInfo.

apply_file_info_opts_fun(Options,InfoFunction) ->
    fun (F)->
        apply_file_info_opts(Options,file:InfoFunction(F,[{time,posix}])) end.

add1(#reader{} = Reader,Name,NameInArchive,#add_opts{read_info = ReadInfo} = Opts)
    when is_list(Name)->
    Res = case ReadInfo(Name) of
        {error,Reason0}->
            {error,{Name,Reason0}};
        {ok,#file_info{type = symlink} = Fi}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            {ok,Linkname} = file:read_link(Name),
            Header = fileinfo_to_header(NameInArchive,Fi,Linkname),
            add_header(Reader,Header,Opts);
        {ok,#file_info{type = regular} = Fi}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            Header = fileinfo_to_header(NameInArchive,Fi,false),
            {ok,Reader2} = add_header(Reader,Header,Opts),
            FileSize = Header#tar_header.size,
            {ok,FileSize,Reader3} = do_copy(Reader2,Name,Opts),
            Padding = skip_padding(FileSize),
            Pad = <<0:Padding/unit:8>>,
            do_write(Reader3,Pad);
        {ok,#file_info{type = directory} = Fi}->
            add_directory(Reader,Name,NameInArchive,Fi,Opts);
        {ok,#file_info{} = Fi}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            Header = fileinfo_to_header(NameInArchive,Fi,false),
            add_header(Reader,Header,Opts)
    end,
    case Res of
        ok->
            ok;
        {ok,_Reader}->
            ok;
        {error,_Reason} = Err->
            Err
    end;
add1(Reader,Bin,NameInArchive,Opts)
    when is_binary(Bin)->
    add_verbose(Opts,"a ~ts~n",[NameInArchive]),
    Now = os:system_time(seconds),
    Header = #tar_header{name = NameInArchive,size = byte_size(Bin),typeflag = $0,atime = add_opts_time(Opts#add_opts.atime,Now),mtime = add_opts_time(Opts#add_opts.mtime,Now),ctime = add_opts_time(Opts#add_opts.ctime,Now),uid = Opts#add_opts.uid,gid = Opts#add_opts.gid,mode = 33188},
    {ok,Reader2} = add_header(Reader,Header,Opts),
    Padding = skip_padding(byte_size(Bin)),
    Data = [Bin, <<0:Padding/unit:8>>],
    case do_write(Reader2,Data) of
        {ok,_Reader3}->
            ok;
        {error,Reason}->
            {error,{NameInArchive,Reason}}
    end.

add_opts_time(undefined,Now) ->
    Now;
add_opts_time(Time,_Now) ->
    Time.

add_directory(Reader,DirName,NameInArchive,Info,Opts) ->
    case file:list_dir(DirName) of
        {ok,[]}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            Header = fileinfo_to_header(NameInArchive,Info,false),
            add_header(Reader,Header,Opts);
        {ok,Files}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            try add_files(Reader,Files,DirName,NameInArchive,Opts) of 
                ok->
                    ok;
                {error,_} = Err->
                    Err
                catch
                    throw:{error,{_Name,_Reason}} = Err->
                        Err;
                    throw:{error,Reason}->
                        {error,{DirName,Reason}} end;
        {error,Reason}->
            {error,{DirName,Reason}}
    end.

add_files(_Reader,[],_Dir,_DirInArchive,_Opts) ->
    ok;
add_files(Reader,[Name| Rest],Dir,DirInArchive,#add_opts{read_info = Info} = Opts) ->
    FullName = filename:join(Dir,Name),
    NameInArchive = filename:join(DirInArchive,Name),
    Res = case Info(FullName) of
        {error,Reason}->
            {error,{FullName,Reason}};
        {ok,#file_info{type = directory} = Fi}->
            add_directory(Reader,FullName,NameInArchive,Fi,Opts);
        {ok,#file_info{type = symlink} = Fi}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            {ok,Linkname} = file:read_link(FullName),
            Header = fileinfo_to_header(NameInArchive,Fi,Linkname),
            add_header(Reader,Header,Opts);
        {ok,#file_info{type = regular} = Fi}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            Header = fileinfo_to_header(NameInArchive,Fi,false),
            {ok,Reader2} = add_header(Reader,Header,Opts),
            FileSize = Header#tar_header.size,
            {ok,FileSize,Reader3} = do_copy(Reader2,FullName,Opts),
            Padding = skip_padding(FileSize),
            Pad = <<0:Padding/unit:8>>,
            do_write(Reader3,Pad);
        {ok,#file_info{} = Fi}->
            add_verbose(Opts,"a ~ts~n",[NameInArchive]),
            Header = fileinfo_to_header(NameInArchive,Fi,false),
            add_header(Reader,Header,Opts)
    end,
    case Res of
        ok->
            add_files(Reader,Rest,Dir,DirInArchive,Opts);
        {ok,ReaderNext}->
            add_files(ReaderNext,Rest,Dir,DirInArchive,Opts);
        {error,_} = Err->
            Err
    end.

format_string(String,Size)
    when length(String) > Size->
    throw({error,{write_string,field_too_long}});
format_string(String,Size) ->
    Ascii = to_ascii(String),
    if byte_size(Ascii) < Size ->
        [Ascii, 0];true ->
        Ascii end.

format_octal(Octal) ->
    iolist_to_binary(io_lib:fwrite("~.8B",[Octal])).

add_header(#reader{} = Reader,#tar_header{} = Header,Opts) ->
    {ok,Iodata} = build_header(Header,Opts),
    do_write(Reader,Iodata).

write_to_block(Block,IoData,Start)
    when is_list(IoData)->
    write_to_block(Block,iolist_to_binary(IoData),Start);
write_to_block(Block,Bin,Start)
    when is_binary(Bin)->
    Size = byte_size(Bin),
    <<Head:Start/unit:8,_:Size/unit:8,Rest/binary>> = Block,
    <<Head:Start/unit:8,Bin/binary,Rest/binary>>.

build_header(#tar_header{} = Header,Opts) ->
    #tar_header{name = Name,mode = Mode,uid = Uid,gid = Gid,size = Size,typeflag = Type,linkname = Linkname,uname = Uname,gname = Gname,devmajor = Devmaj,devminor = Devmin} = Header,
    Mtime = Header#tar_header.mtime,
    Block0 = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
    {Block1,Pax0} = write_string(Block0,0,100,Name,<<"path">>,#{}),
    Block2 = write_octal(Block1,100,8,Mode),
    {Block3,Pax1} = write_numeric(Block2,108,8,Uid,<<"uid">>,Pax0),
    {Block4,Pax2} = write_numeric(Block3,116,8,Gid,<<"gid">>,Pax1),
    {Block5,Pax3} = write_numeric(Block4,124,12,Size,<<"size">>,Pax2),
    {Block6,Pax4} = write_numeric(Block5,136,12,Mtime,<<"">>,Pax3),
    {Block7,Pax5} = write_string(Block6,156,1,<<Type>>,<<"">>,Pax4),
    {Block8,Pax6} = write_string(Block7,157,100,Linkname,<<"linkpath">>,Pax5),
    {Block9,Pax7} = write_string(Block8,265,32,Uname,<<"uname">>,Pax6),
    {Block10,Pax8} = write_string(Block9,297,32,Gname,<<"gname">>,Pax7),
    {Block11,Pax9} = write_numeric(Block10,329,8,Devmaj,<<"">>,Pax8),
    {Block12,Pax10} = write_numeric(Block11,337,8,Devmin,<<"">>,Pax9),
    {Block13,Pax11} = set_path(Block12,Pax10),
    PaxEntry = case maps:size(Pax11) of
        0->
            [];
        _->
            build_pax_entry(Header,Pax11,Opts)
    end,
    Block14 = set_format(Block13,4),
    Block15 = set_checksum(Block14),
    {ok,[PaxEntry, Block15]}.

set_path(Block0,Pax) ->
    case maps:get(<<"path">>,Pax,nil) of
        nil->
            {Block0,Pax};
        PaxPath->
            case split_ustar_path(PaxPath) of
                {ok,UstarName,UstarPrefix}->
                    {Block1,_} = write_string(Block0,0,100,UstarName,<<"">>,#{}),
                    {Block2,_} = write_string(Block1,345,155,UstarPrefix,<<"">>,#{}),
                    {Block2,maps:remove(<<"path">>,Pax)};
                false->
                    {Block0,Pax}
            end
    end.

set_format(Block0,Format)
    when Format =:= 4;
    Format =:= 5->
    Block1 = write_to_block(Block0,<<"ustar\000">>,257),
    write_to_block(Block1,<<"00">>,263);
set_format(_Block,Format) ->
    throw({error,{invalid_format,Format}}).

set_checksum(Block) ->
    Checksum = compute_checksum(Block),
    write_octal(Block,148,8,Checksum).

build_pax_entry(Header,PaxAttrs,Opts) ->
    Path = Header#tar_header.name,
    Filename = filename:basename(Path),
    Dir = filename:dirname(Path),
    Path2 = filename:join([Dir, "PaxHeaders.0", Filename]),
    AsciiPath = to_ascii(Path2),
    Path3 = if byte_size(AsciiPath) > 100 ->
        binary_part(AsciiPath,0,100 - 1);true ->
        AsciiPath end,
    Keys = maps:keys(PaxAttrs),
    SortedKeys = lists:sort(Keys),
    PaxFile = build_pax_file(SortedKeys,PaxAttrs),
    Size = byte_size(PaxFile),
    Padding = (512 - byte_size(PaxFile) rem 512) rem 512,
    Pad = <<0:Padding/unit:8>>,
    PaxHeader = #tar_header{name = unicode:characters_to_list(Path3),size = Size,mtime = Header#tar_header.mtime,atime = Header#tar_header.atime,ctime = Header#tar_header.ctime,typeflag = $x},
    {ok,PaxHeaderData} = build_header(PaxHeader,Opts),
    [PaxHeaderData, PaxFile, Pad].

build_pax_file(Keys,PaxAttrs) ->
    build_pax_file(Keys,PaxAttrs,[]).

build_pax_file([],_,Acc) ->
    unicode:characters_to_binary(Acc);
build_pax_file([K| Rest],Attrs,Acc) ->
    V = maps:get(K,Attrs),
    Size = sizeof(K) + sizeof(V) + 3,
    Size2 = sizeof(Size) + Size,
    Key = to_string(K),
    Value = to_string(V),
    Record = unicode:characters_to_binary(io_lib:format("~B ~ts=~ts\n",[Size2, Key, Value])),
    if byte_size(Record) =/= Size2 ->
        Size3 = byte_size(Record),
        Record2 = io_lib:format("~B ~ts=~ts\n",[Size3, Key, Value]),
        build_pax_file(Rest,Attrs,[Acc, Record2]);true ->
        build_pax_file(Rest,Attrs,[Acc, Record]) end.

sizeof(Bin)
    when is_binary(Bin)->
    byte_size(Bin);
sizeof(List)
    when is_list(List)->
    length(List);
sizeof(N)
    when is_integer(N)->
    byte_size(integer_to_binary(N));
sizeof(N)
    when is_float(N)->
    byte_size(float_to_binary(N)).

to_string(Bin)
    when is_binary(Bin)->
    unicode:characters_to_list(Bin);
to_string(List)
    when is_list(List)->
    List;
to_string(N)
    when is_integer(N)->
    integer_to_list(N);
to_string(N)
    when is_float(N)->
    float_to_list(N).

split_ustar_path(Path) ->
    Len = length(Path),
    NotAscii =  not is_ascii(Path),
    if Len =< 100;
    NotAscii ->
        false;true ->
        PathBin = binary:list_to_bin(Path),
        case binary:split(PathBin,[<<$/>>],[global, trim_all]) of
            [Part]
                when byte_size(Part) >= 100->
                false;
            Parts->
                case lists:last(Parts) of
                    Name
                        when byte_size(Name) >= 100->
                        false;
                    Name->
                        Parts2 = lists:sublist(Parts,length(Parts) - 1),
                        join_split_ustar_path(Parts2,{ok,Name,nil})
                end
        end end.

join_split_ustar_path([],Acc) ->
    Acc;
join_split_ustar_path([Part| _],{ok,_,nil})
    when byte_size(Part) > 155->
    false;
join_split_ustar_path([Part| _],{ok,_Name,Acc})
    when byte_size(Part) + byte_size(Acc) > 155->
    false;
join_split_ustar_path([Part| Rest],{ok,Name,nil}) ->
    join_split_ustar_path(Rest,{ok,Name,Part});
join_split_ustar_path([Part| Rest],{ok,Name,Acc}) ->
    join_split_ustar_path(Rest,{ok,Name,<<Acc/binary,$/,Part/binary>>}).

write_octal(Block,Pos,Size,X) ->
    Octal = zero_pad(format_octal(X),Size - 1),
    if byte_size(Octal) < Size ->
        write_to_block(Block,Octal,Pos);true ->
        throw({error,{write_failed,octal_field_too_long}}) end.

write_string(Block,Pos,Size,Str,PaxAttr,Pax0) ->
    NotAscii =  not is_ascii(Str),
    if PaxAttr =/= <<"">> andalso (length(Str) > Size orelse NotAscii) ->
        Pax1 = maps:put(PaxAttr,Str,Pax0),
        {Block,Pax1};true ->
        Formatted = format_string(Str,Size),
        {write_to_block(Block,Formatted,Pos),Pax0} end.

write_numeric(Block,Pos,Size,X,PaxAttr,Pax0) ->
    Octal = zero_pad(format_octal(X),Size - 1),
    if byte_size(Octal) < Size ->
        {write_to_block(Block,[Octal, 0],Pos),Pax0};PaxAttr =/= <<"">> ->
        Pax1 = maps:put(PaxAttr,X,Pax0),
        {Block,Pax1};true ->
        throw({error,{write_failed,numeric_field_too_long}}) end.

zero_pad(Str,Size)
    when byte_size(Str) >= Size->
    Str;
zero_pad(Str,Size) ->
    Padding = Size - byte_size(Str),
    Pad = binary:copy(<<$0>>,Padding),
    <<Pad/binary,Str/binary>>.

read_block(Reader) ->
    case do_read(Reader,512) of
        eof->
            throw({error,eof});
        {ok,<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,Reader1}->
            case do_read(Reader1,512) of
                eof->
                    eof;
                {ok,<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,_Reader2}->
                    eof;
                {ok,_Block,_Reader2}->
                    throw({error,invalid_end_of_archive});
                {error,_} = Err->
                    throw(Err)
            end;
        {ok,Block,Reader1}
            when is_binary(Block)->
            {ok,Block,Reader1};
        {error,_} = Err->
            throw(Err)
    end.

get_header(#reader{} = Reader) ->
    case read_block(Reader) of
        eof->
            eof;
        {ok,Block,Reader1}->
            convert_header(Block,Reader1)
    end.

to_v7(Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    #header_v7{name = binary_part(Bin,0,100),mode = binary_part(Bin,100,8),uid = binary_part(Bin,108,8),gid = binary_part(Bin,116,8),size = binary_part(Bin,124,12),mtime = binary_part(Bin,136,12),checksum = binary_part(Bin,148,8),typeflag = binary:at(Bin,156),linkname = binary_part(Bin,157,100)};
to_v7(_) ->
    {error,header_block_too_small}.

to_gnu(#header_v7{} = V7,Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    #header_gnu{header_v7 = V7,magic = binary_part(Bin,257,6),version = binary_part(Bin,263,2),uname = binary_part(Bin,265,32),gname = binary_part(Bin,297,32),devmajor = binary_part(Bin,329,8),devminor = binary_part(Bin,337,8),atime = binary_part(Bin,345,12),ctime = binary_part(Bin,357,12),sparse = to_sparse_array(binary_part(Bin,386,24 * 4 + 1)),real_size = binary_part(Bin,483,12)}.

to_star(#header_v7{} = V7,Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    #header_star{header_v7 = V7,magic = binary_part(Bin,257,6),version = binary_part(Bin,263,2),uname = binary_part(Bin,265,32),gname = binary_part(Bin,297,32),devmajor = binary_part(Bin,329,8),devminor = binary_part(Bin,337,8),prefix = binary_part(Bin,345,131),atime = binary_part(Bin,476,12),ctime = binary_part(Bin,488,12),trailer = binary_part(Bin,508,4)}.

to_ustar(#header_v7{} = V7,Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    #header_ustar{header_v7 = V7,magic = binary_part(Bin,257,6),version = binary_part(Bin,263,2),uname = binary_part(Bin,265,32),gname = binary_part(Bin,297,32),devmajor = binary_part(Bin,329,8),devminor = binary_part(Bin,337,8),prefix = binary_part(Bin,345,155)}.

to_sparse_array(Bin)
    when is_binary(Bin)->
    MaxEntries = byte_size(Bin) div 24,
    IsExtended = 1 =:= binary:at(Bin,24 * MaxEntries),
    Entries = parse_sparse_entries(Bin,MaxEntries - 1,[]),
    #sparse_array{entries = Entries,max_entries = MaxEntries,is_extended = IsExtended}.

parse_sparse_entries(<<>>,_,Acc) ->
    Acc;
parse_sparse_entries(_,-1,Acc) ->
    Acc;
parse_sparse_entries(Bin,N,Acc) ->
    case to_sparse_entry(binary_part(Bin,N * 24,24)) of
        nil->
            parse_sparse_entries(Bin,N - 1,Acc);
        Entry = #sparse_entry{}->
            parse_sparse_entries(Bin,N - 1,[Entry| Acc])
    end.

to_sparse_entry(Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 24->
    OffsetBin = binary_part(Bin,0,12),
    NumBytesBin = binary_part(Bin,12,12),
    case {OffsetBin,NumBytesBin} of
        {<<0,0,0,0,0,0,0,0,0,0,0,0>>,<<0,0,0,0,0,0,0,0,0,0,0,0>>}->
            nil;
        _->
            #sparse_entry{offset = parse_numeric(OffsetBin),num_bytes = parse_numeric(NumBytesBin)}
    end.

-spec(get_format(binary()) -> {ok,pos_integer(),header_v7()}|0|{error,term()}).

get_format(Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    do_get_format(to_v7(Bin),Bin).

do_get_format({error,_} = Err,_Bin) ->
    Err;
do_get_format(#header_v7{} = V7,Bin)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    Checksum = parse_octal(V7#header_v7.checksum),
    Chk1 = compute_checksum(Bin),
    Chk2 = compute_signed_checksum(Bin),
    if Checksum =/= Chk1 andalso Checksum =/= Chk2 ->
        0;true ->
        Ustar = to_ustar(V7,Bin),
        Star = to_star(V7,Bin),
        Magic = Ustar#header_ustar.magic,
        Version = Ustar#header_ustar.version,
        Trailer = Star#header_star.trailer,
        Format = if Magic =:= <<"ustar\000">>,
        Trailer =:= <<"tar\000">> ->
            3;Magic =:= <<"ustar\000">> ->
            4;Magic =:= <<"ustar ">>,
        Version =:= <<" \000">> ->
            2;true ->
            1 end,
        {ok,Format,V7} end.

unpack_format(Format,#header_v7{} = V7,Bin,Reader)
    when is_binary(Bin),
    byte_size(Bin) =:= 512->
    Mtime = parse_numeric(V7#header_v7.mtime),
    Header0 = #tar_header{name = parse_string(V7#header_v7.name),mode = parse_numeric(V7#header_v7.mode),uid = parse_numeric(V7#header_v7.uid),gid = parse_numeric(V7#header_v7.gid),size = parse_numeric(V7#header_v7.size),mtime = Mtime,atime = Mtime,ctime = Mtime,typeflag = V7#header_v7.typeflag,linkname = parse_string(V7#header_v7.linkname)},
    Typeflag = Header0#tar_header.typeflag,
    Header1 = if Format > 1 ->
        unpack_modern(Format,V7,Bin,Header0);true ->
        Name = Header0#tar_header.name,
        Header0#tar_header{name = safe_join_path("",Name)} end,
    HeaderOnly = is_header_only_type(Typeflag),
    Header2 = if HeaderOnly ->
        Header1#tar_header{size = 0};true ->
        Header1 end,
    if Typeflag =:= $S ->
        Gnu = to_gnu(V7,Bin),
        RealSize = parse_numeric(Gnu#header_gnu.real_size),
        {Sparsemap,Reader2} = parse_sparse_map(Gnu,Reader),
        Header3 = Header2#tar_header{size = RealSize},
        {Header3,new_sparse_file_reader(Reader2,Sparsemap,RealSize)};true ->
        FileReader = #reg_file_reader{handle = Reader,num_bytes = Header2#tar_header.size,size = Header2#tar_header.size,pos = 0},
        {Header2,FileReader} end.

unpack_modern(Format,#header_v7{} = V7,Bin,#tar_header{} = Header0)
    when is_binary(Bin)->
    Typeflag = Header0#tar_header.typeflag,
    Ustar = to_ustar(V7,Bin),
    H0 = Header0#tar_header{uname = parse_string(Ustar#header_ustar.uname),gname = parse_string(Ustar#header_ustar.gname)},
    H1 = if Typeflag =:= $3 orelse Typeflag =:= $4 ->
        Ma = parse_numeric(Ustar#header_ustar.devmajor),
        Mi = parse_numeric(Ustar#header_ustar.devminor),
        H0#tar_header{devmajor = Ma,devminor = Mi};true ->
        H0 end,
    {Prefix,H2} = case Format of
        4->
            {parse_string(Ustar#header_ustar.prefix),H1};
        3->
            Star = to_star(V7,Bin),
            Prefix0 = parse_string(Star#header_star.prefix),
            Atime0 = Star#header_star.atime,
            Atime = parse_numeric(Atime0),
            Ctime0 = Star#header_star.ctime,
            Ctime = parse_numeric(Ctime0),
            {Prefix0,H1#tar_header{atime = Atime,ctime = Ctime}};
        _->
            {"",H1}
    end,
    Name = H2#tar_header.name,
    H2#tar_header{name = safe_join_path(Prefix,Name)}.

safe_join_path([],Name) ->
    filename:join([Name]);
safe_join_path(Prefix,[]) ->
    filename:join([Prefix]);
safe_join_path(Prefix,Name) ->
    filename:join(Prefix,Name).

new_sparse_file_reader(Reader,Sparsemap,RealSize) ->
    true = validate_sparse_entries(Sparsemap,RealSize),
    #sparse_file_reader{handle = Reader,num_bytes = RealSize,pos = 0,size = RealSize,sparse_map = Sparsemap}.

validate_sparse_entries(Entries,RealSize) ->
    validate_sparse_entries(Entries,RealSize,0,0).

validate_sparse_entries([],_RealSize,_I,_LastOffset) ->
    true;
validate_sparse_entries([#sparse_entry{} = Entry| Rest],RealSize,I,LastOffset) ->
    Offset = Entry#sparse_entry.offset,
    NumBytes = Entry#sparse_entry.num_bytes,
    if Offset > 1 bsl 63 - 1 - NumBytes ->
        throw({error,{invalid_sparse_map_entry,offset_too_large}});Offset + NumBytes > RealSize ->
        throw({error,{invalid_sparse_map_entry,offset_too_large}});I > 0 andalso LastOffset > Offset ->
        throw({error,{invalid_sparse_map_entry,overlapping_offsets}});true ->
        ok end,
    validate_sparse_entries(Rest,RealSize,I + 1,Offset + NumBytes).

-spec(parse_sparse_map(header_gnu(),descriptor_type()) -> {[sparse_entry()],descriptor_type()}).

parse_sparse_map(#header_gnu{sparse = Sparse},Reader)
    when Sparse#sparse_array.is_extended->
    parse_sparse_map(Sparse,Reader,[]);
parse_sparse_map(#header_gnu{sparse = Sparse},Reader) ->
    {Sparse#sparse_array.entries,Reader}.

parse_sparse_map(#sparse_array{is_extended = true,entries = Entries},Reader,Acc) ->
    case read_block(Reader) of
        eof->
            throw({error,eof});
        {ok,Block,Reader2}->
            Sparse2 = to_sparse_array(Block),
            parse_sparse_map(Sparse2,Reader2,Entries ++ Acc)
    end;
parse_sparse_map(#sparse_array{entries = Entries},Reader,Acc) ->
    Sorted = lists:sort(fun (#sparse_entry{offset = A},#sparse_entry{offset = B})->
        A =< B end,Entries ++ Acc),
    {Sorted,Reader}.

compute_checksum(<<H1:148/binary,H2:8/binary,Rest:(512 - 148 - 8)/binary,_/binary>>) ->
    C0 = checksum(H1) + byte_size(H2) * $ ,
    C1 = checksum(Rest),
    C0 + C1.

compute_signed_checksum(<<H1:148/binary,H2:8/binary,Rest:(512 - 148 - 8)/binary,_/binary>>) ->
    C0 = signed_checksum(H1) + byte_size(H2) * $ ,
    C1 = signed_checksum(Rest),
    C0 + C1.

checksum(Bin) ->
    checksum(Bin,0).

checksum(<<A/unsigned,Rest/binary>>,Sum) ->
    checksum(Rest,Sum + A);
checksum(<<>>,Sum) ->
    Sum.

signed_checksum(Bin) ->
    signed_checksum(Bin,0).

signed_checksum(<<A/signed,Rest/binary>>,Sum) ->
    signed_checksum(Rest,Sum + A);
signed_checksum(<<>>,Sum) ->
    Sum.

-spec(parse_numeric(binary()) -> non_neg_integer()).

parse_numeric(<<>>) ->
    0;
parse_numeric(<<First,_/binary>> = Bin) ->
    if First band 128 =/= 0 ->
        Inv = if First band 64 =/= 0 ->
            0;true ->
            255 end,
        Bytes = binary:bin_to_list(Bin),
        Reducer = fun (C,{I,X})->
            C1 = C bxor Inv,
            C2 = if I =:= 0 ->
                C1 band 127;true ->
                C1 end,
            if X bsr 56 > 0 ->
                throw({error,integer_overflow});true ->
                {I + 1,X bsl 8 bor C2} end end,
        {_,N} = lists:foldl(Reducer,{0,0},Bytes),
        if N bsr 63 > 0 ->
            throw({error,integer_overflow});true ->
            if Inv =:= 255 ->
                -1 bxor N;true ->
                N end end;true ->
        parse_octal(Bin) end.

parse_octal(Bin)
    when is_binary(Bin)->
    do_parse_octal(Bin,<<>>).

do_parse_octal(<<>>,<<>>) ->
    0;
do_parse_octal(<<>>,Acc) ->
    case io_lib:fread("~8u",binary:bin_to_list(Acc)) of
        {error,_}->
            throw({error,invalid_tar_checksum});
        {ok,[Octal],[]}->
            Octal;
        {ok,_,_}->
            throw({error,invalid_tar_checksum})
    end;
do_parse_octal(<<$ ,Rest/binary>>,Acc) ->
    do_parse_octal(Rest,Acc);
do_parse_octal(<<0,Rest/binary>>,Acc) ->
    do_parse_octal(Rest,Acc);
do_parse_octal(<<C,Rest/binary>>,Acc) ->
    do_parse_octal(Rest,<<Acc/binary,C>>).

parse_string(Bin)
    when is_binary(Bin)->
    do_parse_string(Bin,<<>>).

do_parse_string(<<>>,Acc) ->
    case unicode:characters_to_list(Acc) of
        Str
            when is_list(Str)->
            Str;
        {incomplete,_Str,_Rest}->
            binary:bin_to_list(Acc);
        {error,_Str,_Rest}->
            throw({error,{bad_header,invalid_string}})
    end;
do_parse_string(<<0,_/binary>>,Acc) ->
    do_parse_string(<<>>,Acc);
do_parse_string(<<C,Rest/binary>>,Acc) ->
    do_parse_string(Rest,<<Acc/binary,C>>).

convert_header(Bin,#reader{pos = Pos} = Reader)
    when byte_size(Bin) =:= 512,
    Pos rem 512 =:= 0->
    case get_format(Bin) of
        0->
            throw({error,bad_header});
        {ok,Format,V7}->
            unpack_format(Format,V7,Bin,Reader);
        {error,Reason}->
            throw({error,{bad_header,Reason}})
    end;
convert_header(Bin,#reader{pos = Pos})
    when byte_size(Bin) =:= 512->
    throw({error,misaligned_read,Pos});
convert_header(Bin,_Reader)
    when byte_size(Bin) =:= 0->
    eof;
convert_header(_Bin,_Reader) ->
    throw({error,eof}).

fileinfo_to_header(Name,#file_info{} = Fi,Link)
    when is_list(Name)->
    BaseHeader = #tar_header{name = Name,mtime = Fi#file_info.mtime,atime = Fi#file_info.atime,ctime = Fi#file_info.ctime,mode = Fi#file_info.mode,uid = Fi#file_info.uid,gid = Fi#file_info.gid,typeflag = $0},
    do_fileinfo_to_header(BaseHeader,Fi,Link).

do_fileinfo_to_header(Header,#file_info{size = Size,type = regular},_Link) ->
    Header#tar_header{size = Size,typeflag = $0};
do_fileinfo_to_header(#tar_header{name = Name} = Header,#file_info{type = directory},_Link) ->
    Header#tar_header{name = Name ++ "/",typeflag = $5};
do_fileinfo_to_header(Header,#file_info{type = symlink},Link) ->
    Header#tar_header{typeflag = $2,linkname = Link};
do_fileinfo_to_header(Header,#file_info{type = device,mode = Mode} = Fi,_Link)
    when Mode band 61440 =:= 8192->
    Header#tar_header{typeflag = $3,devmajor = Fi#file_info.major_device,devminor = Fi#file_info.minor_device};
do_fileinfo_to_header(Header,#file_info{type = device,mode = Mode} = Fi,_Link)
    when Mode band 61440 =:= 24576->
    Header#tar_header{typeflag = $4,devmajor = Fi#file_info.major_device,devminor = Fi#file_info.minor_device};
do_fileinfo_to_header(Header,#file_info{type = other,mode = Mode},_Link)
    when Mode band 61440 =:= 4096->
    Header#tar_header{typeflag = $6};
do_fileinfo_to_header(Header,Fi,_Link) ->
    {error,{invalid_file_type,Header#tar_header.name,Fi}}.

is_ascii(Str)
    when is_list(Str)->
     not lists:any(fun (Char)->
        Char >= 128 end,Str);
is_ascii(Bin)
    when is_binary(Bin)->
    is_ascii1(Bin).

is_ascii1(<<>>) ->
    true;
is_ascii1(<<C,_Rest/binary>>)
    when C >= 128->
    false;
is_ascii1(<<_,Rest/binary>>) ->
    is_ascii1(Rest).

to_ascii(Str)
    when is_list(Str)->
    case is_ascii(Str) of
        true->
            unicode:characters_to_binary(Str);
        false->
            Chars = lists:filter(fun (Char)->
                Char < 128 end,Str),
            unicode:characters_to_binary(Chars)
    end;
to_ascii(Bin)
    when is_binary(Bin)->
    to_ascii(Bin,<<>>).

to_ascii(<<>>,Acc) ->
    Acc;
to_ascii(<<C,Rest/binary>>,Acc)
    when C < 128->
    to_ascii(Rest,<<Acc/binary,C>>);
to_ascii(<<_,Rest/binary>>,Acc) ->
    to_ascii(Rest,Acc).

is_header_only_type($2) ->
    true;
is_header_only_type($1) ->
    true;
is_header_only_type($5) ->
    true;
is_header_only_type(_) ->
    false.

foldl_read(#reader{access = read} = Reader,Fun,Accu,#read_opts{} = Opts)
    when is_function(Fun,4)->
    case foldl_read0(Reader,Fun,Accu,Opts) of
        {ok,Result,_Reader2}->
            Result;
        {error,_} = Err->
            Err
    end;
foldl_read(#reader{access = Access},_Fun,_Accu,_Opts) ->
    {error,{read_mode_expected,Access}};
foldl_read(TarName,Fun,Accu,#read_opts{} = Opts)
    when is_function(Fun,4)->
    try open(TarName,[read| Opts#read_opts.open_mode]) of 
        {ok,#reader{access = read} = Reader}->
            try foldl_read(Reader,Fun,Accu,Opts)
                after _ = close(Reader) end;
        {error,_} = Err->
            Err
        catch
            throw:Err->
                Err end.

foldl_read0(Reader,Fun,Accu,Opts) ->
    try foldl_read1(Fun,Accu,Reader,Opts,#{}) of 
        {ok,_,_} = Ok->
            Ok
        catch
            throw:{error,{Reason,Format,Args}}->
                read_verbose(Opts,Format,Args),
                {error,Reason};
            throw:Err->
                Err end.

foldl_read1(Fun,Accu0,Reader0,Opts,ExtraHeaders) ->
    {ok,Reader1} = skip_unread(Reader0),
    case get_header(Reader1) of
        eof->
            Fun(eof,Reader1,Opts,Accu0);
        {Header,Reader2}->
            case Header#tar_header.typeflag of
                $x->
                    {ExtraHeaders2,Reader3} = parse_pax(Reader2),
                    ExtraHeaders3 = maps:merge(ExtraHeaders,ExtraHeaders2),
                    foldl_read1(Fun,Accu0,Reader3,Opts,ExtraHeaders3);
                $L->
                    {RealName,Reader3} = get_real_name(Reader2),
                    ExtraHeaders2 = maps:put(<<"path">>,parse_string(RealName),ExtraHeaders),
                    foldl_read1(Fun,Accu0,Reader3,Opts,ExtraHeaders2);
                $K->
                    {RealName,Reader3} = get_real_name(Reader2),
                    ExtraHeaders2 = maps:put(<<"linkpath">>,parse_string(RealName),ExtraHeaders),
                    foldl_read1(Fun,Accu0,Reader3,Opts,ExtraHeaders2);
                _->
                    Header1 = merge_pax(Header,ExtraHeaders),
                    {ok,NewAccu,Reader3} = Fun(Header1,Reader2,Opts,Accu0),
                    foldl_read1(Fun,NewAccu,Reader3,Opts,#{})
            end
    end.

-spec(merge_pax(tar_header(),#{binary() => binary()}) -> tar_header()).

merge_pax(Header,ExtraHeaders)
    when is_map(ExtraHeaders)->
    do_merge_pax(Header,maps:to_list(ExtraHeaders)).

do_merge_pax(Header,[]) ->
    Header;
do_merge_pax(Header,[{<<"path">>,Path}| Rest]) ->
    do_merge_pax(Header#tar_header{name = unicode:characters_to_list(Path)},Rest);
do_merge_pax(Header,[{<<"linkpath">>,LinkPath}| Rest]) ->
    do_merge_pax(Header#tar_header{linkname = unicode:characters_to_list(LinkPath)},Rest);
do_merge_pax(Header,[{<<"gname">>,Gname}| Rest]) ->
    do_merge_pax(Header#tar_header{gname = unicode:characters_to_list(Gname)},Rest);
do_merge_pax(Header,[{<<"uname">>,Uname}| Rest]) ->
    do_merge_pax(Header#tar_header{uname = unicode:characters_to_list(Uname)},Rest);
do_merge_pax(Header,[{<<"uid">>,Uid}| Rest]) ->
    Uid2 = binary_to_integer(Uid),
    do_merge_pax(Header#tar_header{uid = Uid2},Rest);
do_merge_pax(Header,[{<<"gid">>,Gid}| Rest]) ->
    Gid2 = binary_to_integer(Gid),
    do_merge_pax(Header#tar_header{gid = Gid2},Rest);
do_merge_pax(Header,[{<<"atime">>,Atime}| Rest]) ->
    Atime2 = parse_pax_time(Atime),
    do_merge_pax(Header#tar_header{atime = Atime2},Rest);
do_merge_pax(Header,[{<<"mtime">>,Mtime}| Rest]) ->
    Mtime2 = parse_pax_time(Mtime),
    do_merge_pax(Header#tar_header{mtime = Mtime2},Rest);
do_merge_pax(Header,[{<<"ctime">>,Ctime}| Rest]) ->
    Ctime2 = parse_pax_time(Ctime),
    do_merge_pax(Header#tar_header{ctime = Ctime2},Rest);
do_merge_pax(Header,[{<<"size">>,Size}| Rest]) ->
    Size2 = binary_to_integer(Size),
    do_merge_pax(Header#tar_header{size = Size2},Rest);
do_merge_pax(Header,[{<<"SCHILY.xattr.",_Key/binary>>,_Value}| Rest]) ->
    do_merge_pax(Header,Rest);
do_merge_pax(Header,[_Ignore| Rest]) ->
    do_merge_pax(Header,Rest).

-spec(parse_pax_time(binary()) -> tar_time()).

parse_pax_time(Bin)
    when is_binary(Bin)->
    TotalNano = case binary:split(Bin,[<<$.>>]) of
        [SecondsStr, NanoStr0]->
            Seconds = binary_to_integer(SecondsStr),
            if byte_size(NanoStr0) < 9 ->
                PaddingN = 9 - byte_size(NanoStr0),
                Padding = binary:copy(<<$0>>,PaddingN),
                NanoStr1 = <<NanoStr0/binary,Padding/binary>>,
                Nano = binary_to_integer(NanoStr1),
                Seconds * 1000000000 + Nano;byte_size(NanoStr0) > 9 ->
                NanoStr1 = binary_part(NanoStr0,0,9),
                Nano = binary_to_integer(NanoStr1),
                Seconds * 1000000000 + Nano;true ->
                Seconds * 1000000000 + binary_to_integer(NanoStr0) end;
        [SecondsStr]->
            binary_to_integer(SecondsStr) * 1000000000
    end,
    Micro = TotalNano div 1000,
    Mega = Micro div 1000000000000,
    Secs = Micro div 1000000 - Mega * 1000000,
    Secs.

parse_pax(#reg_file_reader{handle = Handle,num_bytes = 0}) ->
    {#{},Handle};
parse_pax(#reg_file_reader{handle = Handle0,num_bytes = NumBytes}) ->
    case do_read(Handle0,NumBytes) of
        {ok,Bytes,Handle1}->
            do_parse_pax(Handle1,Bytes,#{});
        {error,_} = Err->
            throw(Err)
    end.

do_parse_pax(Reader,<<>>,Headers) ->
    {Headers,Reader};
do_parse_pax(Reader,Bin,Headers) ->
    {Key,Value,Residual} = parse_pax_record(Bin),
    NewHeaders = maps:put(Key,Value,Headers),
    do_parse_pax(Reader,Residual,NewHeaders).

parse_pax_record(Bin)
    when is_binary(Bin)->
    case binary:split(Bin,[<<$\n>>]) of
        [Record, Residual]->
            case binary:split(Record,[<<$ >>],[trim_all]) of
                [_Len, Record1]->
                    case binary:split(Record1,[<<$=>>],[trim_all]) of
                        [AttrName, AttrValue]->
                            {AttrName,AttrValue,Residual};
                        _Other->
                            throw({error,malformed_pax_record})
                    end;
                _Other->
                    throw({error,malformed_pax_record})
            end;
        _Other->
            throw({error,malformed_pax_record})
    end.

get_real_name(#reg_file_reader{handle = Handle,num_bytes = 0}) ->
    {"",Handle};
get_real_name(#reg_file_reader{handle = Handle0,num_bytes = NumBytes}) ->
    case do_read(Handle0,NumBytes) of
        {ok,RealName,Handle1}->
            {RealName,Handle1};
        {error,_} = Err->
            throw(Err)
    end;
get_real_name(#sparse_file_reader{num_bytes = NumBytes} = Reader0) ->
    case do_read(Reader0,NumBytes) of
        {ok,RealName,Reader1}->
            {RealName,Reader1};
        {error,_} = Err->
            throw(Err)
    end.

skip_file(#reg_file_reader{handle = Handle0,pos = Pos,size = Size} = Reader) ->
    Padding = skip_padding(Size),
    AbsPos = Handle0#reader.pos + (Size - Pos) + Padding,
    case do_position(Handle0,AbsPos) of
        {ok,_,Handle1}->
            Reader#reg_file_reader{handle = Handle1,num_bytes = 0,pos = Size};
        Err->
            throw(Err)
    end;
skip_file(#sparse_file_reader{pos = Pos,size = Size} = Reader) ->
    case do_read(Reader,Size - Pos) of
        {ok,_,Reader2}->
            Reader2;
        Err->
            throw(Err)
    end.

skip_padding(0) ->
    0;
skip_padding(Size)
    when Size rem 512 =:= 0->
    0;
skip_padding(Size)
    when Size =< 512->
    512 - Size;
skip_padding(Size) ->
    512 - Size rem 512.

skip_unread(#reader{pos = Pos} = Reader0)
    when Pos rem 512 > 0->
    Padding = skip_padding(Pos + 512),
    AbsPos = Pos + Padding,
    case do_position(Reader0,AbsPos) of
        {ok,_,Reader1}->
            {ok,Reader1};
        Err->
            throw(Err)
    end;
skip_unread(#reader{} = Reader) ->
    {ok,Reader};
skip_unread(#reg_file_reader{handle = Handle,num_bytes = 0}) ->
    skip_unread(Handle);
skip_unread(#reg_file_reader{} = Reader) ->
    #reg_file_reader{handle = Handle} = skip_file(Reader),
    {ok,Handle};
skip_unread(#sparse_file_reader{handle = Handle,num_bytes = 0}) ->
    skip_unread(Handle);
skip_unread(#sparse_file_reader{} = Reader) ->
    #sparse_file_reader{handle = Handle} = skip_file(Reader),
    {ok,Handle}.

write_extracted_element(#tar_header{name = Name,typeflag = Type},Bin,#read_opts{output = memory} = Opts) ->
    case typeflag(Type) of
        regular->
            read_verbose(Opts,"x ~ts~n",[Name]),
            {ok,{Name,Bin}};
        _->
            ok
    end;
write_extracted_element(#tar_header{name = Name0} = Header,Bin,Opts) ->
    Name1 = make_safe_path(Name0,Opts),
    Created = case typeflag(Header#tar_header.typeflag) of
        regular->
            create_regular(Name1,Name0,Bin,Opts);
        directory->
            read_verbose(Opts,"x ~ts~n",[Name0]),
            create_extracted_dir(Name1,Opts);
        symlink->
            read_verbose(Opts,"x ~ts~n",[Name0]),
            LinkName = safe_link_name(Header,Opts),
            create_symlink(Name1,LinkName,Opts);
        Device
            when Device =:= char orelse Device =:= block->
            create_regular(Name1,Name0,<<>>,Opts);
        fifo->
            create_regular(Name1,Name0,<<>>,Opts);
        Other->
            read_verbose(Opts,"x ~ts - unsupported type ~p~n",[Name0, Other]),
            not_written
    end,
    case Created of
        ok->
            set_extracted_file_info(Name1,Header);
        not_written->
            ok
    end.

make_safe_path([$/| Path],Opts) ->
    make_safe_path(Path,Opts);
make_safe_path(Path0,#read_opts{cwd = Cwd}) ->
    case filelib:safe_relative_path(Path0,Cwd) of
        unsafe->
            throw({error,{Path0,unsafe_path}});
        Path->
            filename:absname(Path,Cwd)
    end.

safe_link_name(#tar_header{linkname = Path0},#read_opts{cwd = Cwd}) ->
    case filelib:safe_relative_path(Path0,Cwd) of
        unsafe->
            throw({error,{Path0,unsafe_symlink}});
        Path->
            Path
    end.

create_regular(Name,NameInArchive,Bin,Opts) ->
    case write_extracted_file(Name,Bin,Opts) of
        not_written->
            read_verbose(Opts,"x ~ts - exists, not created~n",[NameInArchive]),
            not_written;
        Ok->
            read_verbose(Opts,"x ~ts~n",[NameInArchive]),
            Ok
    end.

create_extracted_dir(Name,_Opts) ->
    case file:make_dir(Name) of
        ok->
            ok;
        {error,enotsup}->
            not_written;
        {error,eexist}->
            not_written;
        {error,enoent}->
            make_dirs(Name,dir);
        {error,Reason}->
            throw({error,Reason})
    end.

create_symlink(Name,Linkname,Opts) ->
    case file:make_symlink(Linkname,Name) of
        ok->
            ok;
        {error,enoent}->
            ok = make_dirs(Name,file),
            create_symlink(Name,Linkname,Opts);
        {error,eexist}->
            not_written;
        {error,enotsup}->
            read_verbose(Opts,"x ~ts - symbolic links not supported~n",[Name]),
            not_written;
        {error,Reason}->
            throw({error,Reason})
    end.

write_extracted_file(Name,Bin,Opts) ->
    Write = case Opts#read_opts.keep_old_files of
        true->
            case file:read_file_info(Name) of
                {ok,_}->
                    false;
                _->
                    true
            end;
        false->
            true
    end,
    case Write of
        true->
            write_file(Name,Bin);
        false->
            not_written
    end.

write_file(Name,Bin) ->
    case file:write_file(Name,Bin) of
        ok->
            ok;
        {error,enoent}->
            case make_dirs(Name,file) of
                ok->
                    write_file(Name,Bin);
                {error,Reason}->
                    throw({error,Reason})
            end;
        {error,Reason}->
            throw({error,Reason})
    end.

set_extracted_file_info(_,#tar_header{typeflag = $2}) ->
    ok;
set_extracted_file_info(_,#tar_header{typeflag = $1}) ->
    ok;
set_extracted_file_info(Name,#tar_header{typeflag = $3} = Header) ->
    set_device_info(Name,Header);
set_extracted_file_info(Name,#tar_header{typeflag = $4} = Header) ->
    set_device_info(Name,Header);
set_extracted_file_info(Name,#tar_header{mtime = Mtime,mode = Mode}) ->
    Info = #file_info{mode = Mode,mtime = Mtime},
    file:write_file_info(Name,Info,[{time,posix}]).

set_device_info(Name,#tar_header{} = Header) ->
    Mtime = Header#tar_header.mtime,
    Mode = Header#tar_header.mode,
    Devmajor = Header#tar_header.devmajor,
    Devminor = Header#tar_header.devminor,
    Info = #file_info{mode = Mode,mtime = Mtime,major_device = Devmajor,minor_device = Devminor},
    file:write_file_info(Name,Info).

make_dirs(Name,file) ->
    filelib:ensure_dir(Name);
make_dirs(Name,dir) ->
    filelib:ensure_dir(filename:join(Name,"*")).

read_verbose(#read_opts{verbose = true},Format,Args) ->
    io:format(Format,Args);
read_verbose(_,_,_) ->
    ok.

add_verbose(#add_opts{verbose = true},Format,Args) ->
    io:format(Format,Args);
add_verbose(_,_,_) ->
    ok.

do_write(#reader{handle = Handle,func = Fun} = Reader0,Data)
    when is_function(Fun,2)->
    case Fun(write,{Handle,Data}) of
        ok->
            {ok,Pos,Reader1} = do_position(Reader0,{cur,0}),
            {ok,Reader1#reader{pos = Pos}};
        {error,_} = Err->
            Err
    end.

do_copy(#reader{func = Fun} = Reader,Source,#add_opts{chunk_size = 0} = Opts)
    when is_function(Fun,2)->
    do_copy(Reader,Source,Opts#add_opts{chunk_size = 65536});
do_copy(#reader{func = Fun} = Reader,Source,#add_opts{chunk_size = ChunkSize})
    when is_function(Fun,2)->
    case file:open(Source,[read, binary]) of
        {ok,SourceFd}->
            case copy_chunked(Reader,SourceFd,ChunkSize,0) of
                {ok,_Copied,_Reader2} = Ok->
                    _ = file:close(SourceFd),
                    Ok;
                Err->
                    _ = file:close(SourceFd),
                    throw(Err)
            end;
        Err->
            throw(Err)
    end.

copy_chunked(#reader{} = Reader,Source,ChunkSize,Copied) ->
    case file:read(Source,ChunkSize) of
        {ok,Bin}->
            {ok,Reader2} = do_write(Reader,Bin),
            copy_chunked(Reader2,Source,ChunkSize,Copied + byte_size(Bin));
        eof->
            {ok,Copied,Reader};
        Other->
            Other
    end.

do_position(#reader{handle = Handle,func = Fun} = Reader,Pos)
    when is_function(Fun,2)->
    case Fun(position,{Handle,Pos}) of
        {ok,NewPos}->
            {ok,AbsPos} = Fun(position,{Handle,{cur,0}}),
            {ok,NewPos,Reader#reader{pos = AbsPos}};
        Other->
            Other
    end.

do_read(#reg_file_reader{handle = Handle,pos = Pos,size = Size} = Reader,Len) ->
    NumBytes = Size - Pos,
    ActualLen = if NumBytes - Len < 0 ->
        NumBytes;true ->
        Len end,
    case do_read(Handle,ActualLen) of
        {ok,Bin,Handle2}->
            NewPos = Pos + ActualLen,
            NumBytes2 = Size - NewPos,
            Reader1 = Reader#reg_file_reader{handle = Handle2,pos = NewPos,num_bytes = NumBytes2},
            {ok,Bin,Reader1};
        Other->
            Other
    end;
do_read(#sparse_file_reader{} = Reader,Len) ->
    do_sparse_read(Reader,Len);
do_read(#reader{pos = Pos,handle = Handle,func = Fun} = Reader,Len)
    when is_function(Fun,2)->
    case Fun(read2,{Handle,Len}) of
        {ok,List}
            when is_list(List)->
            Bin = list_to_binary(List),
            NewPos = Pos + byte_size(Bin),
            {ok,Bin,Reader#reader{pos = NewPos}};
        {ok,Bin}
            when is_binary(Bin)->
            NewPos = Pos + byte_size(Bin),
            {ok,Bin,Reader#reader{pos = NewPos}};
        Other->
            Other
    end.

do_sparse_read(Reader,Len) ->
    do_sparse_read(Reader,Len,<<>>).

do_sparse_read(#sparse_file_reader{sparse_map = [#sparse_entry{num_bytes = 0}| Entries]} = Reader0,Len,Acc) ->
    Reader1 = Reader0#sparse_file_reader{sparse_map = Entries},
    do_sparse_read(Reader1,Len,Acc);
do_sparse_read(#sparse_file_reader{sparse_map = [],pos = Pos,size = Size} = Reader0,Len,Acc)
    when Pos < Size->
    {ok,Bin,Reader1} = read_sparse_hole(Reader0,Size,Len),
    do_sparse_read(Reader1,Len - byte_size(Bin),<<Acc/binary,Bin/binary>>);
do_sparse_read(#sparse_file_reader{sparse_map = []} = Reader,_Len,Acc) ->
    {ok,Acc,Reader};
do_sparse_read(#sparse_file_reader{} = Reader,0,Acc) ->
    {ok,Acc,Reader};
do_sparse_read(#sparse_file_reader{sparse_map = [#sparse_entry{offset = Offset}| _],pos = Pos} = Reader0,Len,Acc)
    when Pos < Offset->
    {ok,Bin,Reader1} = read_sparse_hole(Reader0,Offset,Offset - Pos),
    do_sparse_read(Reader1,Len - byte_size(Bin),<<Acc/binary,Bin/binary>>);
do_sparse_read(#sparse_file_reader{sparse_map = [Entry| Entries],pos = Pos} = Reader0,Len,Acc) ->
    EndPos = Entry#sparse_entry.offset + Entry#sparse_entry.num_bytes,
    NumBytes = EndPos - Pos,
    ActualLen = if Len > NumBytes ->
        NumBytes;true ->
        Len end,
    case do_read(Reader0#sparse_file_reader.handle,ActualLen) of
        {ok,Bin,Handle}->
            BytesRead = byte_size(Bin),
            ActualEndPos = Pos + BytesRead,
            Reader1 = if ActualEndPos =:= EndPos ->
                Reader0#sparse_file_reader{sparse_map = Entries};true ->
                Reader0 end,
            Size = Reader1#sparse_file_reader.size,
            NumBytes2 = Size - ActualEndPos,
            Reader2 = Reader1#sparse_file_reader{handle = Handle,pos = ActualEndPos,num_bytes = NumBytes2},
            do_sparse_read(Reader2,Len - byte_size(Bin),<<Acc/binary,Bin/binary>>);
        Other->
            Other
    end.

read_sparse_hole(#sparse_file_reader{pos = Pos} = Reader,Offset,Len) ->
    N = Offset - Pos,
    N2 = if N > Len ->
        Len;true ->
        N end,
    Bin = <<0:N2/unit:8>>,
    NumBytes = Reader#sparse_file_reader.size - (Pos + N2),
    {ok,Bin,Reader#sparse_file_reader{num_bytes = NumBytes,pos = Pos + N2}}.

-spec(do_close(tar_descriptor()) -> ok|{error,term()}).

do_close(#reader{handle = Handle,func = Fun})
    when is_function(Fun,2)->
    Fun(close,Handle).

extract_opts(List) ->
    extract_opts(List,default_options()).

table_opts(List) ->
    read_opts(List,default_options()).

default_options() ->
    {ok,Cwd} = file:get_cwd(),
    #read_opts{cwd = Cwd}.

extract_opts([keep_old_files| Rest],Opts) ->
    extract_opts(Rest,Opts#read_opts{keep_old_files = true});
extract_opts([{cwd,Cwd}| Rest],Opts) ->
    extract_opts(Rest,Opts#read_opts{cwd = Cwd});
extract_opts([{files,Files}| Rest],Opts) ->
    Set = ordsets:from_list(Files),
    extract_opts(Rest,Opts#read_opts{files = Set});
extract_opts([memory| Rest],Opts) ->
    extract_opts(Rest,Opts#read_opts{output = memory});
extract_opts([compressed| Rest],Opts = #read_opts{open_mode = OpenMode}) ->
    extract_opts(Rest,Opts#read_opts{open_mode = [compressed| OpenMode]});
extract_opts([cooked| Rest],Opts = #read_opts{open_mode = OpenMode}) ->
    extract_opts(Rest,Opts#read_opts{open_mode = [cooked| OpenMode]});
extract_opts([verbose| Rest],Opts) ->
    extract_opts(Rest,Opts#read_opts{verbose = true});
extract_opts([Other| Rest],Opts) ->
    extract_opts(Rest,read_opts([Other],Opts));
extract_opts([],Opts) ->
    Opts.

read_opts([compressed| Rest],Opts = #read_opts{open_mode = OpenMode}) ->
    read_opts(Rest,Opts#read_opts{open_mode = [compressed| OpenMode]});
read_opts([cooked| Rest],Opts = #read_opts{open_mode = OpenMode}) ->
    read_opts(Rest,Opts#read_opts{open_mode = [cooked| OpenMode]});
read_opts([verbose| Rest],Opts) ->
    read_opts(Rest,Opts#read_opts{verbose = true});
read_opts([_| Rest],Opts) ->
    read_opts(Rest,Opts);
read_opts([],Opts) ->
    Opts.