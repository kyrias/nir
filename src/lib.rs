#[macro_use]
extern crate nom;

mod modes;
mod serialize;

use modes::channel_modes;
pub use modes::{AddedChannelMode, ChannelModeChange, RemovedChannelMode};
pub use serialize::Serialize;

trait SplitToVec {
    type Pattern;

    fn split_to_vec(&self, pattern: Self::Pattern) -> Vec<String>;
}

impl<'a> SplitToVec for &'a [u8] {
    type Pattern = &'a [u8];

    fn split_to_vec(&self, pattern: &[u8]) -> Vec<String> {
        self.split(|b| pattern.contains(b))
            .map(|s| String::from_utf8_lossy(&s).into_owned())
            .collect()
    }
}

impl SplitToVec for String {
    type Pattern = &'static str;

    fn split_to_vec(&self, pattern: &str) -> Vec<String> {
        self.split(pattern).map(|s| s.to_owned()).collect()
    }
}

impl<T> SplitToVec for Option<T>
where
    T: SplitToVec + Clone,
{
    type Pattern = <T as SplitToVec>::Pattern;

    fn split_to_vec(&self, pattern: Self::Pattern) -> Vec<String> {
        self.clone()
            .map(|inner| inner.split_to_vec(pattern))
            .unwrap_or_default()
    }
}

fn from_dec(input: String) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(&input, 10)
}

named!(
    spaces<&[u8], &[u8]>,
    is_a!(b" ")
);

#[derive(PartialEq, Eq, Debug)]
pub struct Prefix(String);

fn prefix(input: &[u8]) -> nom::IResult<&[u8], Prefix> {
    let (rest, _) = try_parse!(input, tag!(":"));
    let (rest, prefix) = try_parse!(rest, is_not!(" "));
    let prefix = String::from_utf8_lossy(prefix).into_owned();
    Ok((rest, Prefix(prefix)))
}

named!(
    argument_middle<&[u8], String>,
    do_parse!(
        peek!(verify!(nom::anychar, |val| val != ':')) >>
        argument: is_not!(b" \0\r\n") >>
        (String::from_utf8_lossy(argument).into_owned())
    )
);

named!(
    argument_trailing<&[u8], String>,
    do_parse!(
        tag!(b":") >>
        argument: take_until_either!(b"\0\r\n") >>
        (String::from_utf8_lossy(argument).into_owned())
    )
);

named!(
    argument_maybe_last<&[u8], String>,
    alt!(
        argument_middle |
        argument_trailing
    )
);

named!(
    argument_middle_u8<&[u8], u8>,
    do_parse!(
        argument: map_res!(argument_middle, from_dec) >>
        (argument)
    )
);

named!(
    argument_trailing_u8<&[u8], u8>,
    do_parse!(
        argument: map_res!(argument_trailing, from_dec) >>
        (argument)
    )
);

named!(
    argument_maybe_last_u8<&[u8], u8>,
    alt!(
        argument_middle_u8 |
        argument_trailing_u8
    )
);

// Command parsers
#[derive(PartialEq, Eq, Debug)]
pub enum Command {
    Pass {
        password: String,
    },
    Nick {
        nickname: String,
        hopcount: Option<u8>,
    },
    User {
        username: String,
        hostname: String,
        servername: String,
        realname: String,
    },
    Server {
        servername: String,
        hopcount: u8,
        info: String,
    },
    Oper {
        user: String,
        password: String,
    },
    Quit {
        message: Option<String>,
    },
    Squit {
        server: String,
        comment: String,
    },
    Join {
        channels: Vec<String>,
        keys: Vec<String>,
    },
    Part {
        channels: Vec<String>,
    },
    Mode {
        target: String,
        modechanges: Option<Vec<ChannelModeChange>>,
    },
    Topic {
        channel: String,
        topic: Option<String>,
    },
    Names {
        channels: Vec<String>,
    },
    List {
        channels: Vec<String>,
        server: Option<String>,
    },
    Invite {
        nickname: String,
        channel: String,
    },
    Kick {
        channel: String,
        user: String,
        comment: Option<String>,
    },
    Version {
        server: Option<String>,
    },
    Stats {
        query: Option<String>,
        server: Option<String>,
    },
    Links {
        remote_server: Option<String>,
        server_mask: Option<String>,
    },
    Time {
        server: Option<String>,
    },
    Connect {
        target_server: String,
        port: Option<String>,
        remote_server: Option<String>,
    },
    Trace {
        server: Option<String>,
    },
    Admin {
        server: Option<String>,
    },
    Info {
        server: Option<String>,
    },
    Privmsg {
        receivers: Vec<String>,
        message: String,
    },
    Notice {
        nickname: String,
        text: String,
    },
    Who {
        name: Option<String>,
        o: Option<String>,
    },
    Whois {
        server: Option<String>,
        nickmasks: Vec<String>,
    },
    Whowas {
        nickname: String,
        count: Option<String>,
        server: Option<String>,
    },
    Kill {
        nickname: String,
        comment: String,
    },
    Ping {
        server1: String,
        server2: Option<String>,
    },
    Pong {
        daemon1: String,
        daemon2: Option<String>,
    },
    Error {
        message: String,
    },
    Away {
        message: Option<String>,
    },
    Rehash,
    Restart,
    Summon {
        user: String,
        server: Option<String>,
    },
    Users {
        server: Option<String>,
    },
    Wallops {
        text: String,
    },
    Userhost {
        nicknames: Vec<String>,
    },
    Ison {
        nicknames: Vec<String>,
    },
}

named!(
    command_pass<&[u8], Command>,
    do_parse!(
        tag!(b"PASS") >>
        spaces >>
        password: argument_maybe_last >>
        (Command::Pass { password: password.to_string() })
    )
);

named!(
    command_nick<&[u8], Command>,
    do_parse!(
        tag!(b"NICK") >>
        spaces >>
        nickname: argument_maybe_last >>
        opt!(spaces) >>
        hopcount: opt!(argument_maybe_last_u8) >>
        (Command::Nick { nickname: nickname.to_string(), hopcount: hopcount })
    )
);

named!(
    command_user<&[u8], Command>,
    do_parse!(
        tag!(b"USER") >>
        spaces >>
        username: argument_middle >>
        spaces >>
        hostname: argument_middle >>
        spaces >>
        servername: argument_middle >>
        spaces >>
        realname: argument_maybe_last >>
        (Command::User { username: username.to_string(),
                         hostname: hostname.to_string(),
                         servername: servername.to_string(),
                         realname: realname.to_string() })
    )
);

named!(
    command_server<&[u8], Command>,
    do_parse!(
        tag!(b"SERVER") >>
        spaces >>
        servername: argument_middle >>
        spaces >>
        hopcount: argument_middle_u8 >>
        spaces >>
        info: argument_maybe_last >>
        (Command::Server { servername: servername.to_string(), hopcount: hopcount, info: info.to_string() })
    )
);

named!(
    command_oper<&[u8], Command>,
    do_parse!(
        tag!(b"OPER") >>
        spaces >>
        user: argument_middle >>
        spaces >>
        password: argument_maybe_last >>
        (Command::Oper { user: user.to_string(), password: password.to_string() })
    )
);

named!(
    command_quit<&[u8], Command>,
    do_parse!(
        tag!(b"QUIT") >>
        opt!(spaces) >>
        message: opt!(argument_maybe_last) >>
        (Command::Quit { message: message.map(|m| m.to_string()) })
    )
);

named!(
    command_squit<&[u8], Command>,
    do_parse!(
        tag!(b"SQUIT") >>
        spaces >>
        server: argument_middle >>
        spaces >>
        comment: argument_maybe_last >>
        (Command::Squit { server: server.to_string(), comment: comment.to_string() })
    )
);

named!(
    command_join<&[u8], Command>,
    do_parse!(
        tag!(b"JOIN") >>
        spaces >>
        channels: argument_maybe_last >>
        opt!(spaces) >>
        keys: opt!(argument_maybe_last) >>
        (Command::Join { channels: channels.split_to_vec(","),
                         keys: keys.split_to_vec(",") })
    )
);

named!(
    command_part<&[u8], Command>,
    do_parse!(
        tag!(b"PART") >>
        spaces >>
        channels: argument_maybe_last >>
        (Command::Part { channels: channels.split_to_vec(",") })
    )
);

named!(channel_mode<&[u8], Command>,
    do_parse!(
        target: argument_maybe_last >>
        spaces >>
        modechanges: opt!(channel_modes) >>
        (Command::Mode { target: target,
                         modechanges: modechanges })
    )
);

named!(
    command_mode<&[u8], Command>,
    do_parse!(
        tag!(b"MODE") >>
        spaces >>
        modes: channel_mode >>
        (modes)
    )
);

named!(
    command_topic<&[u8], Command>,
    do_parse!(
        tag!(b"TOPIC") >>
        spaces >>
        channel: argument_middle >>
        opt!(spaces) >>
        topic: opt!(argument_maybe_last) >>
        (Command::Topic { channel: channel.to_string(), topic: topic.map(|t| t.to_string()) })
    )
);

named!(
    command_names<&[u8], Command>,
    do_parse!(
        tag!(b"NAMES") >>
        opt!(spaces) >>
        channels: opt!(argument_maybe_last) >>
        (Command::Names { channels: channels.split_to_vec(",") })
    )
);

named!(
    command_list<&[u8], Command>,
    do_parse!(
        tag!(b"LIST") >>
        opt!(spaces) >>
        channels: opt!(argument_middle) >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::List { channels: channels.split_to_vec(","),
                         server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_invite<&[u8], Command>,
    do_parse!(
        tag!(b"INVITE") >>
        spaces >>
        nickname: argument_middle >>
        spaces >>
        channel: argument_maybe_last >>
        (Command::Invite { nickname: nickname.to_string(), channel: channel.to_string() })
    )
);

named!(
    command_kick<&[u8], Command>,
    do_parse!(
        tag!(b"KICK") >>
        spaces >>
        channel: argument_middle >>
        spaces >>
        user: argument_maybe_last >>
        opt!(spaces) >>
        comment: opt!(argument_maybe_last) >>
        (Command::Kick { channel: channel.to_string(), user: user.to_string(), comment: comment.map(|c| c.to_string()) })
    )
);

named!(
    command_version<&[u8], Command>,
    do_parse!(
        tag!(b"VERSION") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Version { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_stats<&[u8], Command>,
    do_parse!(
        tag!(b"STATS") >>
        opt!(spaces) >>
        query: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Stats { query: query.map(|q| q.to_string()), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_links_all_arguments<&[u8], Command>,
    do_parse!(
        tag!(b"LINKS") >>
        spaces >>
        remote_server: argument_middle >>
        spaces >>
        server_mask: argument_maybe_last >>
        (Command::Links { remote_server: Some(remote_server.to_string()), server_mask: Some(server_mask.to_string()) })
    )
);

named!(
    command_links_opt_server_mask<&[u8], Command>,
    do_parse!(
        tag!(b"LINKS") >>
        opt!(spaces) >>
        server_mask: opt!(argument_maybe_last) >>
        (Command::Links { remote_server: None, server_mask: server_mask.map(|s| s.to_string()) })
    )
);

named!(
    command_links<&[u8], Command>,
    alt!(
        command_links_all_arguments |
        command_links_opt_server_mask
    )
);

named!(
    command_time<&[u8], Command>,
    do_parse!(
        tag!(b"TIME") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Time { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_connect<&[u8], Command>,
    do_parse!(
        tag!(b"CONNECT") >>
        spaces >>
        target_server: argument_maybe_last >>
        opt!(spaces) >>
        port: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        remote_server: opt!(argument_maybe_last) >>
        (Command::Connect { target_server: target_server.to_string(),
                            port: port.map(|p| p.to_string()),
                            remote_server: remote_server.map(|r| r.to_string()) })
    )
);

named!(
    command_trace<&[u8], Command>,
    do_parse!(
        tag!(b"TRACE") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Trace { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_admin<&[u8], Command>,
    do_parse!(
        tag!(b"ADMIN") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Admin { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_info<&[u8], Command>,
    do_parse!(
        tag!(b"INFO") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Info { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_privmsg<&[u8], Command>,
    do_parse!(
        tag!(b"PRIVMSG") >>
        spaces >>
        receivers: argument_middle >>
        spaces >>
        message: argument_maybe_last >>
        (Command::Privmsg { receivers: receivers.split_to_vec(","),
                            message: message.to_string() })
    )
);

named!(
    command_notice<&[u8], Command>,
    do_parse!(
        tag!(b"NOTICE") >>
        spaces >>
        nickname: argument_middle >>
        spaces >>
        text: argument_maybe_last >>
        (Command::Notice { nickname: nickname.to_string(), text: text.to_string() })
    )
);

named!(
    command_who<&[u8], Command>,
    do_parse!(
        tag!(b"WHO") >>
        spaces >>
        name: opt!(
            do_parse!(
                name: argument_maybe_last >>
                spaces >>
                (name)
            )
        ) >>
        o: opt!(argument_maybe_last) >>
        (Command::Who { name: name.map(|n| n.to_string()), o: o.map(|o| o.to_string()) })
    )
);

named!(
    command_whois<&[u8], Command>,
    do_parse!(
        tag!(b"WHOIS") >>
        spaces >>
        server: opt!(
            do_parse!(
                server: argument_middle >>
                spaces >>
                (server)
            )
        ) >>
        nickmasks: argument_maybe_last >>
        (Command::Whois { server: server.map(|s| s.to_string()),
                          nickmasks: nickmasks.split_to_vec(",") })
    )
);

named!(
    command_whowas<&[u8], Command>,
    do_parse!(
        tag!(b"WHOWAS") >>
        spaces >>
        nickname: argument_maybe_last >>
        opt!(spaces) >>
        count: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Whowas { nickname: nickname.to_string(), count: count.map(|c| c.to_string()), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_kill<&[u8], Command>,
    do_parse!(
        tag!(b"KILL") >>
        spaces >>
        nickname: argument_middle >>
        spaces >>
        comment: argument_maybe_last >>
        (Command::Kill { nickname: nickname.to_string(), comment: comment.to_string() })
    )
);

named!(
    command_ping<&[u8], Command>,
    do_parse!(
        tag!(b"PING") >>
        spaces >>
        server1: argument_maybe_last >>
        opt!(spaces) >>
        server2: opt!(argument_maybe_last) >>
        (Command::Ping { server1: server1.to_string(), server2: server2.map(|s2| s2.to_string()) })
    )
);

named!(
    command_pong<&[u8], Command>,
    do_parse!(
        tag!(b"PONG") >>
        spaces >>
        daemon1: argument_maybe_last >>
        opt!(spaces) >>
        daemon2: opt!(argument_maybe_last) >>
        (Command::Pong { daemon1: daemon1.to_string(), daemon2: daemon2.map(|s2| s2.to_string()) })
    )
);

named!(
    command_error<&[u8], Command>,
    do_parse!(
        tag!(b"ERROR") >>
        spaces >>
        message: argument_maybe_last >>
        (Command::Error { message: message.to_string() })
    )
);

named!(
    command_away<&[u8], Command>,
    do_parse!(
        tag!(b"AWAY") >>
        message: opt!(
            do_parse!(
                spaces >>
                message: argument_maybe_last >>
                (message)
            )
        ) >>
        (Command::Away { message: message.map(|m| m.to_string()) })
    )
);

named!(
    command_rehash<&[u8], Command>,
    do_parse!(
        tag!(b"REHASH") >>
        (Command::Rehash)
    )
);

named!(
    command_restart<&[u8], Command>,
    do_parse!(
        tag!(b"RESTART") >>
        (Command::Restart)
    )
);

named!(
    command_summon<&[u8], Command>,
    do_parse!(
        tag!(b"SUMMON") >>
        spaces >>
        user: argument_maybe_last >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Summon { user: user.to_string(), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_users<&[u8], Command>,
    do_parse!(
        tag!(b"USERS") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Users { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_wallops<&[u8], Command>,
    do_parse!(
        tag!(b"WALLOPS") >>
        spaces >>
        text: argument_maybe_last >>
        (Command::Wallops { text: text.to_string() })
    )
);

named!(
    command_userhost<&[u8], Command>,
    do_parse!(
        tag!(b"USERHOST") >>
        spaces >>
        nick1: argument_maybe_last >>
        opt!(spaces) >>
        nick2: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        nick3: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        nick4: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        nick5: opt!(argument_maybe_last) >>
        (Command::Userhost {
            nicknames: vec![Some(nick1), nick2, nick3, nick4, nick5]
                .iter()
                .flat_map(|n| n.clone())
                .collect() })
    )
);

named!(
    command_ison<&[u8], Command>,
    do_parse!(
        tag!(b"ISON") >>
        spaces >>
        nicknames: take_until_either!(b"\0\r\n") >>
        (Command::Ison { nicknames: nicknames.split_to_vec(b" ") })
    )
);

named!(
    command<&[u8], Command>,
    switch!(
        peek!(is_not!(b" \r")),
        b"PASS" => call!(command_pass) |
        b"NICK" => call!(command_nick) |
        b"USER" => call!(command_user) |
        b"SERVER" => call!(command_server) |
        b"OPER" => call!(command_oper) |
        b"QUIT" => call!(command_quit) |
        b"SQUIT" => call!(command_squit) |
        b"JOIN" => call!(command_join) |
        b"PART" => call!(command_part) |
        b"MODE" => call!(command_mode) |
        b"TOPIC" => call!(command_topic) |
        b"NAMES" => call!(command_names) |
        b"LIST" => call!(command_list) |
        b"INVITE" => call!(command_invite) |
        b"KICK" => call!(command_kick) |
        b"VERSION" => call!(command_version) |
        b"STATS" => call!(command_stats) |
        b"LINKS" => call!(command_links) |
        b"TIME" => call!(command_time) |
        b"CONNECT" => call!(command_connect) |
        b"TRACE" => call!(command_trace) |
        b"ADMIN" => call!(command_admin) |
        b"INFO" => call!(command_info) |
        b"PRIVMSG" => call!(command_privmsg) |
        b"NOTICE" => call!(command_notice) |
        b"WHO" => call!(command_who) |
        b"WHOIS" => call!(command_whois) |
        b"WHOWAS" => call!(command_whowas) |
        b"KILL" => call!(command_kill) |
        b"PING" => call!(command_ping) |
        b"PONG" => call!(command_pong) |
        b"ERROR" => call!(command_error) |
        b"AWAY" => call!(command_away) |
        b"REHASH" => call!(command_rehash) |
        b"RESTART" => call!(command_restart) |
        b"SUMMON" => call!(command_summon) |
        b"USERS" => call!(command_users) |
        b"WALLOPS" => call!(command_wallops) |
        b"USERHOST" => call!(command_userhost) |
        b"ISON" => call!(command_ison)
    )
);

#[derive(PartialEq, Eq, Debug)]
pub struct Message {
    pub prefix: Option<Prefix>,
    pub command: Command,
}

named!(
    pub parse_message<&[u8], Message>,
    do_parse!(
        prefix: opt!(do_parse!(prefix: prefix >> spaces >> (prefix))) >>
        command: command >>
        tag!(b"\r\n") >>
        (Message { prefix: prefix, command: command })
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass() {
        assert_eq!(
            command_pass(b"PASS password\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Pass {
                    password: "password".into()
                }
            ))
        );
        assert_eq!(
            command_pass(b"PASS :password\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Pass {
                    password: "password".into()
                }
            ))
        );

        assert_eq!(
            command_pass(b"PASS  password\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Pass {
                    password: "password".into()
                }
            ))
        );
        assert_eq!(
            command_pass(b"PASS  :password\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Pass {
                    password: "password".into()
                }
            ))
        );
    }

    #[test]
    fn nick() {
        assert_eq!(
            command_nick(b"NICK nickname\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Nick {
                    nickname: "nickname".into(),
                    hopcount: None
                }
            ))
        );
        assert_eq!(
            command_nick(b"NICK :nickname\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Nick {
                    nickname: "nickname".into(),
                    hopcount: None
                }
            ))
        );

        assert_eq!(
            command_nick(b"NICK  nickname  42\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Nick {
                    nickname: "nickname".into(),
                    hopcount: Some(42)
                }
            ))
        );
        assert_eq!(
            command_nick(b"NICK nickname :42\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Nick {
                    nickname: "nickname".into(),
                    hopcount: Some(42)
                }
            ))
        );
    }

    #[test]
    fn user() {
        assert_eq!(
            command_user(b"USER user host server real\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::User {
                    username: "user".to_string(),
                    hostname: "host".to_string(),
                    servername: "server".to_string(),
                    realname: "real".to_string()
                }
            ))
        );

        assert_eq!(
            command_user(b"USER user  host   server    :real name\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::User {
                    username: "user".to_string(),
                    hostname: "host".to_string(),
                    servername: "server".to_string(),
                    realname: "real name".to_string()
                }
            ))
        );
    }

    #[test]
    fn server() {
        assert_eq!(
            command_server(b"SERVER foo 5 something\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Server {
                    servername: "foo".to_string(),
                    hopcount: 5,
                    info: "something".to_string()
                }
            ))
        );
        assert_eq!(
            command_server(b"SERVER foo    5  :this is some server!\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Server {
                    servername: "foo".to_string(),
                    hopcount: 5,
                    info: "this is some server!".to_string()
                }
            ))
        );
    }

    #[test]
    fn oper() {
        assert_eq!(
            command_oper(b"OPER user pass\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Oper {
                    user: "user".to_string(),
                    password: "pass".to_string()
                }
            ))
        );
        assert_eq!(
            command_oper(b"OPER user  :pass\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Oper {
                    user: "user".to_string(),
                    password: "pass".to_string()
                }
            ))
        );
    }

    #[test]
    fn quit() {
        assert_eq!(
            command_quit(b"QUIT\r\n"),
            Ok((&b"\r\n"[..], Command::Quit { message: None }))
        );
        assert_eq!(
            command_quit(b"QUIT bye\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Quit {
                    message: Some("bye".to_string())
                }
            ))
        );
        assert_eq!(
            command_quit(b"QUIT  :good bye\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Quit {
                    message: Some("good bye".to_string())
                }
            ))
        );
    }

    #[test]
    fn squit() {
        assert_eq!(
            command_squit(b"SQUIT server comment\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Squit {
                    server: "server".to_string(),
                    comment: "comment".to_string()
                }
            ))
        );
        assert_eq!(
            command_squit(b"SQUIT server  :comment\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Squit {
                    server: "server".to_string(),
                    comment: "comment".to_string()
                }
            ))
        );
    }

    #[test]
    fn join() {
        assert_eq!(
            command_join(b"JOIN #foo\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Join {
                    channels: vec!["#foo".to_string()],
                    keys: vec![],
                }
            ))
        );
        assert_eq!(
            command_join(b"JOIN #foo,#bar\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Join {
                    channels: vec!["#foo".to_string(), "#bar".to_string()],
                    keys: vec![],
                }
            ))
        );
        assert_eq!(
            command_join(b"JOIN #foo,#bar  baz,quux\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Join {
                    channels: vec!["#foo".to_string(), "#bar".to_string()],
                    keys: vec!["baz".to_string(), "quux".to_string()],
                }
            ))
        );
    }

    #[test]
    fn part() {
        assert_eq!(
            command_part(b"PART #foo\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Part {
                    channels: vec!["#foo".to_string()],
                }
            ))
        );
        assert_eq!(
            command_part(b"PART  #foo,#bar\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Part {
                    channels: vec!["#foo".to_string(), "#bar".to_string()],
                }
            ))
        );
    }

    #[test]
    fn mode() {
        let command = b"MODE #foo +b-q+l-i foo bar!*@* 42\r\n";
        let expected = Command::Mode {
            target: "#foo".to_string(),
            modechanges: Some(vec![
                ChannelModeChange::Added(AddedChannelMode::Ban("foo".to_string())),
                ChannelModeChange::Removed(RemovedChannelMode::Quiet("bar!*@*".to_string())),
                ChannelModeChange::Added(AddedChannelMode::Limit(42)),
                ChannelModeChange::Removed(RemovedChannelMode::InviteOnly),
            ]),
        };

        assert_eq!(
            command_mode(&command[..]),
            Ok((&b"\r\n"[..], expected))
        );
    }

    #[test]
    fn topic() {
        assert_eq!(
            command_topic(b"TOPIC #channel\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Topic {
                    channel: "#channel".to_string(),
                    topic: None
                }
            ))
        );
        assert_eq!(
            command_topic(b"TOPIC #channel something\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Topic {
                    channel: "#channel".to_string(),
                    topic: Some("something".to_string())
                }
            ))
        );
        assert_eq!(
            command_topic(b"TOPIC #channel  :something else\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Topic {
                    channel: "#channel".to_string(),
                    topic: Some("something else".to_string())
                }
            ))
        );
    }

    #[test]
    fn names() {
        assert_eq!(
            command_names(b"NAMES\r\n"),
            Ok((&b"\r\n"[..], Command::Names { channels: vec![] }))
        );
        assert_eq!(
            command_names(b"NAMES  :#foo,#bar\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Names {
                    channels: vec!["#foo".to_string(), "#bar".to_string()],
                }
            ))
        );
    }

    #[test]
    fn list() {
        assert_eq!(
            command_list(b"LIST\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::List {
                    channels: vec![],
                    server: None,
                }
            ))
        );
        assert_eq!(
            command_list(b"LIST #channel\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::List {
                    channels: vec!["#channel".to_string()],
                    server: None,
                }
            ))
        );
        assert_eq!(
            command_list(b"LIST #channel  :irc.example.org\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::List {
                    channels: vec!["#channel".to_string()],
                    server: Some("irc.example.org".to_string()),
                }
            ))
        );
    }

    #[test]
    fn invite() {
        assert_eq!(
            command_invite(b"INVITE person #channel\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Invite {
                    nickname: "person".to_string(),
                    channel: "#channel".to_string()
                }
            ))
        );
        assert_eq!(
            command_invite(b"INVITE person  :#channel\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Invite {
                    nickname: "person".to_string(),
                    channel: "#channel".to_string()
                }
            ))
        );
    }

    #[test]
    fn kick() {
        assert_eq!(
            command_kick(b"KICK #channel person\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Kick {
                    channel: "#channel".to_string(),
                    user: "person".to_string(),
                    comment: None
                }
            ))
        );
        assert_eq!(
            command_kick(b"KICK #channel person  :some message\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Kick {
                    channel: "#channel".to_string(),
                    user: "person".to_string(),
                    comment: Some("some message".to_string())
                }
            ))
        );
    }

    #[test]
    fn version() {
        assert_eq!(
            command_version(b"VERSION\r\n"),
            Ok((&b"\r\n"[..], Command::Version { server: None }))
        );
        assert_eq!(
            command_version(b"VERSION irc.example.org\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Version {
                    server: Some("irc.example.org".to_string())
                }
            ))
        );
        assert_eq!(
            command_version(b"VERSION  :irc.example.org\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Version {
                    server: Some("irc.example.org".to_string())
                }
            ))
        );
    }

    // Stats { query: Option<String>, server: Option<String> },
    #[test]
    fn stats() {}

    // Links { remote_server: Option<String>, server_mask: Option<String> },
    #[test]
    fn links() {}

    // Time { server: Option<String> },
    #[test]
    fn time() {}

    // Connect { target_server: String, port: Option<String>, remote_server: Option<String> },
    #[test]
    fn connect() {}

    // Trace { server: Option<String> },
    #[test]
    fn trace() {}

    // Admin { server: Option<String> },
    #[test]
    fn admin() {}

    // Info { server: Option<String> },
    #[test]
    fn info() {}

    // Privmsg { receivers: Vec<String>, message: String },
    #[test]
    fn privmsg() {}

    // Notice { nickname: String, text: String },
    #[test]
    fn notice() {}

    // Who { name: Option<String>, o: Option<String> },
    #[test]
    fn who() {}

    // Whois { server: Option<String>, nickmasks: Vec<String> },
    #[test]
    fn whois() {}

    // Whowas { nickname: String, count: Option<String>, server: Option<String> },
    #[test]
    fn whowas() {}

    // Kill { nickname: String, comment: String },
    #[test]
    fn kill() {}

    // Ping { server1: String, server2: Option<String> },
    #[test]
    fn ping() {}

    // Pong { daemon1: String, daemon2: Option<String> },
    #[test]
    fn pong() {}

    // Error { message: String },
    #[test]
    fn error() {}

    // Away { message: Option<String> },
    #[test]
    fn away() {}

    // Rehash,
    #[test]
    fn rehash() {}

    // Restart,
    #[test]
    fn restart() {}

    // Summon { user: String, server: Option<String> },
    #[test]
    fn summon() {}

    // Users { server: Option<String> },
    #[test]
    fn users() {}

    // Wallops { text: String },
    #[test]
    fn wallops() {}

    // Userhost { nicknames: Vec<String> },
    #[test]
    fn userhost() {}

    // Ison { nicknames: Vec<String> },
    #[test]
    fn ison() {}

    #[test]
    fn test_prefix() {
        assert_eq!(
            prefix(b":foo.bar PRIVMSG #baz :quux"),
            Ok((&b" PRIVMSG #baz :quux"[..], Prefix("foo.bar".to_string())))
        );
    }

    #[test]
    fn test_argument_middle() {
        assert_eq!(
            argument_middle(b"foo :baz"),
            Ok((&b" :baz"[..], "foo".to_owned()))
        );
    }

    #[test]
    fn test_argument_middle_initial_colon_not_allowed() {
        assert_eq!(
            argument_middle(b":foo baz"),
            Err(nom::Err::Error(nom::Context::Code(
                &b":foo baz"[..],
                nom::ErrorKind::Verify
            )))
        );
    }

    #[test]
    fn test_argument_trailing() {
        assert_eq!(
            argument_trailing(b":foo bar baz\r\n"),
            Ok((&b"\r\n"[..], "foo bar baz".to_owned()))
        );
    }

    #[test]
    fn test_argument_trailing_empty() {
        assert_eq!(
            argument_trailing(b":\r\n"),
            Ok((&b"\r\n"[..], "".to_owned()))
        );
    }

    #[test]
    fn test_command_privmsg() {
        assert_eq!(
            command_privmsg(b"PRIVMSG #foo,#bar baz\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Privmsg {
                    receivers: vec!["#foo".to_string(), "#bar".to_string()],
                    message: "baz".to_string(),
                }
            ))
        );

        assert_eq!(
            command_privmsg(b"PRIVMSG #foo,#bar :baz quux\r\n"),
            Ok((
                &b"\r\n"[..],
                Command::Privmsg {
                    receivers: vec!["#foo".to_string(), "#bar".to_string()],
                    message: "baz quux".to_string(),
                }
            ))
        );
    }

    #[test]
    fn test_message() {
        assert_eq!(
            parse_message(b":irc.example.org PRIVMSG #foo :bar baz\r\n"),
            Ok((
                &b""[..],
                Message {
                    prefix: Some(Prefix("irc.example.org".to_string())),
                    command: Command::Privmsg {
                        receivers: vec!["#foo".into()],
                        message: "bar baz".into(),
                    },
                }
            ))
        );
    }

    #[test]
    fn test_whois() {
        assert_eq!(
            parse_message(b"WHO kyrias\r\n"),
            Ok((
                &b""[..],
                Message {
                    prefix: None,
                    command: Command::Who {
                        name: None,
                        o: Some("kyrias".into())
                    }
                }
            ))
        );
        assert_eq!(
            parse_message(b"WHO kyrias foo\r\n"),
            Ok((
                &b""[..],
                Message {
                    prefix: None,
                    command: Command::Who {
                        name: Some("kyrias".into()),
                        o: Some("foo".into())
                    }
                }
            ))
        );
        assert_eq!(
            parse_message(b"WHOIS kyrias\r\n"),
            Ok((
                &b""[..],
                Message {
                    prefix: None,
                    command: Command::Whois {
                        server: None,
                        nickmasks: vec!["kyrias".into()],
                    },
                }
            ))
        );
        assert_eq!(
            parse_message(b"WHOIS kyrias,demize\r\n"),
            Ok((
                &b""[..],
                Message {
                    prefix: None,
                    command: Command::Whois {
                        server: None,
                        nickmasks: vec!["kyrias".into(), "demize".into()],
                    },
                }
            ))
        );
        assert_eq!(
            parse_message(b"WHOIS chat.freenode.net kyrias,demize\r\n"),
            Ok((
                &b""[..],
                Message {
                    prefix: None,
                    command: Command::Whois {
                        server: Some("chat.freenode.net".into()),
                        nickmasks: vec!["kyrias".into(), "demize".into()],
                    },
                }
            ))
        );
    }
}
