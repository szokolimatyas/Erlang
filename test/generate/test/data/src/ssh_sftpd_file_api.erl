-file("ssh_sftpd_file_api.erl", 1).

-module(ssh_sftpd_file_api).

-callback(close(file:io_device(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(delete(file:name(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(del_dir(file:name(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(get_cwd(State::term()) -> {{ok,Dir::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(is_dir(file:name(),State::term()) -> {boolean(),State::term()}).

-callback(list_dir(file:name(),State::term()) -> {{ok,Filenames::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(make_dir(Dir::term(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(make_symlink(Path2::term(),Path::term(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(open(Path::term(),Flags::term(),State::term()) -> {{ok,IoDevice::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(position(file:io_device(),Offs::term(),State::term()) -> {{ok,NewPosition::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(read(file:io_device(),Len::term(),State::term()) -> {{ok,Data::term()},State::term()}|{eof,State::term()}|{{error,Reason::term()},State::term()}).

-callback(read_link(file:name(),State::term()) -> {{ok,FileName::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(read_link_info(file:name(),State::term()) -> {{ok,FileInfo::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(read_file_info(file:name(),State::term()) -> {{ok,FileInfo::term()},State::term()}|{{error,Reason::term()},State::term()}).

-callback(rename(file:name(),file:name(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(write(file:io_device(),Data::term(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).

-callback(write_file_info(file:name(),Info::term(),State::term()) -> {ok,State::term()}|{{error,Reason::term()},State::term()}).