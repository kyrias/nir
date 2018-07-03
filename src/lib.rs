#[macro_use]
extern crate nom;


fn from_dec(input: &str) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(input, 10)
}


named!(
    spaces<&str, &str>,
    is_a!(" ")
);


#[derive(PartialEq, Eq, Debug)]
pub struct Prefix(String);

named!(
    prefix<&str, Prefix>,
    do_parse!(
        tag!(":") >>
        pre: is_not!(" ") >>
        (Prefix(pre.to_string()))
    )
);


named!(
    argument_middle<&str, &str>,
    do_parse!(
        peek!(verify!(nom::anychar, |val| val != ':')) >>
        argument: is_not!(" \0\r\n") >>
        (argument)
    )
);

named!(
    argument_trailing<&str, &str>,
    do_parse!(
        tag!(":") >>
        argument: take_until_either!("\0\r\n") >>
        (argument)
    )
);

named!(
    argument_maybe_last<&str, &str>,
    alt!(
        argument_middle |
        argument_trailing
    )
);

named!(
    argument_middle_u8<&str, u8>,
    do_parse!(
        peek!(verify!(take!(1), |val| val != ":")) >>
        argument: map_res!(is_not!(" \0\r\n"), from_dec) >>
        (argument)
    )
);

named!(
    argument_trailing_u8<&str, u8>,
    do_parse!(
        tag!(":") >>
        argument: map_res!(take_until_either!("\0\r\n"), from_dec) >>
        (argument)
    )
);

named!(
    argument_maybe_last_u8<&str, u8>,
    alt!(
        argument_middle_u8 |
        argument_trailing_u8
    )
);


// Command parsers
#[derive(PartialEq, Eq, Debug)]
pub enum Command {
    Pass { password: String },
    Nick { nickname: String, hopcount: Option<u8> },
    User { username: String, hostname: String, servername: String, realname: String },
    Server { servername: String, hopcount: u8, info: String },
    Oper { user: String, password: String },
    Quit { message: Option<String> },
    Squit { server: String, comment: String },
    Join { channels: Vec<String>, keys: Vec<String> },
    Part { channels: Vec<String> },
    Mode { target: String, modes: String, limit: Option<String>, user: Option<String>, banmask: Option<String> },
    Topic { channel: String, topic: Option<String> },
    Names { channels: Vec<String> },
    List { channels: Vec<String>, server: Option<String> },
    Invite { nickname: String, channel: String },
    Kick { channel: String, user: String, comment: Option<String> },
    Version { server: Option<String> },
    Stats { query: Option<String>, server: Option<String> },
    Links { remote_server: Option<String>, server_mask: Option<String> },
    Time { server: Option<String> },
    Connect { target_server: String, port: Option<String>, remote_server: Option<String> },
    Trace { server: Option<String> },
    Admin { server: Option<String> },
    Info { server: Option<String> },
    Privmsg { receivers: Vec<String>, message: String },
    Notice { nickname: String, text: String },
    Who { name: Option<String>, o: Option<String> },
    Whois { server: Option<String>, nickmasks: Vec<String> },
    Whowas { nickname: String, count: Option<String>, server: Option<String> },
    Kill { nickname: String, comment: String },
    Ping { server1: String, server2: Option<String> },
    Pong { daemon1: String, daemon2: Option<String> },
    Error { message: String },
    Away { message: Option<String> },
    Rehash,
    Restart,
    Summon { user: String, server: Option<String> },
    Users { server: Option<String> },
    Wallops { text: String },
    Userhost { nicknames: Vec<String> },
    Ison { nicknames: Vec<String> },
}

named!(
    command_pass<&str, Command>,
    do_parse!(
        tag!("PASS") >>
        spaces >>
        password: argument_maybe_last >>
        (Command::Pass { password: password.to_string() })
    )
);

named!(
    command_nick<&str, Command>,
    do_parse!(
        tag!("NICK") >>
        spaces >>
        nickname: argument_maybe_last >>
        opt!(spaces) >>
        hopcount: opt!(argument_maybe_last_u8) >>
        (Command::Nick { nickname: nickname.to_string(), hopcount: hopcount })
    )
);

named!(
    command_user<&str, Command>,
    do_parse!(
        tag!("USER") >>
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
    command_server<&str, Command>,
    do_parse!(
        tag!("SERVER") >>
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
    command_oper<&str, Command>,
    do_parse!(
        tag!("OPER") >>
        spaces >>
        user: argument_middle >>
        spaces >>
        password: argument_maybe_last >>
        (Command::Oper { user: user.to_string(), password: password.to_string() })
    )
);

named!(
    command_quit<&str, Command>,
    do_parse!(
        tag!("QUIT") >>
        opt!(spaces) >>
        message: opt!(argument_maybe_last) >>
        (Command::Quit { message: message.map(|m| m.to_string()) })
    )
);

named!(
    command_squit<&str, Command>,
    do_parse!(
        tag!("SQUIT") >>
        spaces >>
        server: argument_middle >>
        spaces >>
        comment: argument_maybe_last >>
        (Command::Squit { server: server.to_string(), comment: comment.to_string() })
    )
);

named!(
    command_join<&str, Command>,
    do_parse!(
        tag!("JOIN") >>
        spaces >>
        channels: argument_maybe_last >>
        opt!(spaces) >>
        keys: opt!(argument_maybe_last) >>
        (Command::Join { channels: channels.split(",").map(|c| c.to_string()).collect(),
                         keys: keys
                             .map(|ks| ks.split(",").map(|k| k.to_string()).collect())
                             .unwrap_or_default() })
    )
);

named!(
    command_part<&str, Command>,
    do_parse!(
        tag!("PART") >>
        spaces >>
        channels: argument_maybe_last >>
        (Command::Part { channels: channels.split(",").map(|c| c.to_string()).collect() })
    )
);

// TODO: This doesn't actually parse them properly, since the order in practice depends on the
// order of the modes.  https://tools.ietf.org/html/rfc2812#section-3.2.3
// I'm really not sure how to parse this properly.
named!(
    command_mode<&str, Command>,
    do_parse!(
        tag!("MODE") >>
        spaces >>
        target: argument_middle >>
        spaces >>
        modes: argument_middle >>
        opt!(spaces) >>
        limit: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        user: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        banmask: opt!(argument_maybe_last) >>
        (Command::Mode { target: target.to_string(),
                         modes: modes.to_string(),
                         limit: limit.map(|l| l.to_string()),
                         user: user.map(|u| u.to_string()),
                         banmask: banmask.map(|b| b.to_string()) })
    )
);

named!(
    command_topic<&str, Command>,
    do_parse!(
        tag!("TOPIC") >>
        spaces >>
        channel: argument_middle >>
        opt!(spaces) >>
        topic: opt!(argument_maybe_last) >>
        (Command::Topic { channel: channel.to_string(), topic: topic.map(|t| t.to_string()) })
    )
);

named!(
    command_names<&str, Command>,
    do_parse!(
        tag!("NAMES") >>
        opt!(spaces) >>
        channels: opt!(argument_maybe_last) >>
        (Command::Names { channels: channels.unwrap_or_default().split(",").map(|c| c.to_string()).collect() })
    )
);

named!(
    command_list<&str, Command>,
    do_parse!(
        tag!("LIST") >>
        opt!(spaces) >>
        channels: opt!(argument_middle) >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::List { channels: channels.unwrap_or_default().split(",").map(|c| c.to_string()).collect(),
                         server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_invite<&str, Command>,
    do_parse!(
        tag!("INVITE") >>
        spaces >>
        nickname: argument_middle >>
        spaces >>
        channel: argument_maybe_last >>
        (Command::Invite { nickname: nickname.to_string(), channel: channel.to_string() })
    )
);

named!(
    command_kick<&str, Command>,
    do_parse!(
        tag!("KICK") >>
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
    command_version<&str, Command>,
    do_parse!(
        tag!("VERSION") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Version { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_stats<&str, Command>,
    do_parse!(
        tag!("STATS") >>
        opt!(spaces) >>
        query: opt!(argument_maybe_last) >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Stats { query: query.map(|q| q.to_string()), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_links_all_arguments<&str, Command>,
    do_parse!(
        tag!("LINKS") >>
        spaces >>
        remote_server: argument_middle >>
        spaces >>
        server_mask: argument_maybe_last >>
        (Command::Links { remote_server: Some(remote_server.to_string()), server_mask: Some(server_mask.to_string()) })
    )
);

named!(
    command_links_opt_server_mask<&str, Command>,
    do_parse!(
        tag!("LINKS") >>
        opt!(spaces) >>
        server_mask: opt!(argument_maybe_last) >>
        (Command::Links { remote_server: None, server_mask: server_mask.map(|s| s.to_string()) })
    )
);

named!(
    command_links<&str, Command>,
    alt!(
        command_links_all_arguments |
        command_links_opt_server_mask
    )
);

named!(
    command_time<&str, Command>,
    do_parse!(
        tag!("TIME") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Time { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_connect<&str, Command>,
    do_parse!(
        tag!("CONNECT") >>
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
    command_trace<&str, Command>,
    do_parse!(
        tag!("TRACE") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Trace { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_admin<&str, Command>,
    do_parse!(
        tag!("ADMIN") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Admin { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_info<&str, Command>,
    do_parse!(
        tag!("INFO") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Info { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_privmsg<&str, Command>,
    do_parse!(
        tag!("PRIVMSG") >>
        spaces >>
        receivers: argument_middle >>
        spaces >>
        message: argument_maybe_last >>
        (Command::Privmsg { receivers: receivers.split(",").map(|r| r.to_string()).collect(),
                            message: message.to_string() })
    )
);

named!(
    command_notice<&str, Command>,
    do_parse!(
        tag!("NOTICE") >>
        nickname: argument_middle >>
        spaces >>
        text: argument_maybe_last >>
        (Command::Notice { nickname: nickname.to_string(), text: text.to_string() })
    )
);

named!(
    command_who<&str, Command>,
    do_parse!(
        tag!("WHO") >>
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
    command_whois<&str, Command>,
    do_parse!(
        tag!("WHOIS") >>
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
                          nickmasks: nickmasks.split(",").map(|n| n.to_string()).collect() })
    )
);

named!(
    command_whowas<&str, Command>,
    do_parse!(
        tag!("WHOWAS") >>
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
    command_kill<&str, Command>,
    do_parse!(
        tag!("KILL") >>
        spaces >>
        nickname: argument_middle >>
        spaces >>
        comment: argument_maybe_last >>
        (Command::Kill { nickname: nickname.to_string(), comment: comment.to_string() })
    )
);

named!(
    command_ping<&str, Command>,
    do_parse!(
        tag!("PING") >>
        spaces >>
        server1: argument_maybe_last >>
        opt!(spaces) >>
        server2: opt!(argument_maybe_last) >>
        (Command::Ping { server1: server1.to_string(), server2: server2.map(|s2| s2.to_string()) })
    )
);

named!(
    command_pong<&str, Command>,
    do_parse!(
        tag!("PONG") >>
        spaces >>
        daemon1: argument_maybe_last >>
        opt!(spaces) >>
        daemon2: opt!(argument_maybe_last) >>
        (Command::Pong { daemon1: daemon1.to_string(), daemon2: daemon2.map(|s2| s2.to_string()) })
    )
);

named!(
    command_error<&str, Command>,
    do_parse!(
        tag!("ERROR") >>
        spaces >>
        message: argument_maybe_last >>
        (Command::Error { message: message.to_string() })
    )
);

named!(
    command_away<&str, Command>,
    do_parse!(
        tag!("AWAY") >>
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
    command_rehash<&str, Command>,
    do_parse!(
        tag!("REHASH") >>
        (Command::Rehash)
    )
);

named!(
    command_restart<&str, Command>,
    do_parse!(
        tag!("RESTART") >>
        (Command::Restart)
    )
);

named!(
    command_summon<&str, Command>,
    do_parse!(
        tag!("SUMMON") >>
        spaces >>
        user: argument_maybe_last >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Summon { user: user.to_string(), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_users<&str, Command>,
    do_parse!(
        tag!("USERS") >>
        opt!(spaces) >>
        server: opt!(argument_maybe_last) >>
        (Command::Users { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_wallops<&str, Command>,
    do_parse!(
        tag!("WALLOPS") >>
        spaces >>
        text: argument_maybe_last >>
        (Command::Wallops { text: text.to_string() })
    )
);

named!(
    command_userhost<&str, Command>,
    do_parse!(
        tag!("USERHOST") >>
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
        (Command::Userhost { nicknames: vec![Some(nick1), nick2, nick3, nick4, nick5].iter().flat_map(|n| n.map(|n| n.to_string())).collect() })
    )
);

named!(
    command_ison<&str, Command>,
    do_parse!(
        tag!("ISON") >>
        spaces >>
        nicknames: take_until_either!("\0\r\n") >>
        (Command::Ison { nicknames: nicknames.split(" ").map(|n| n.to_string()).collect() })
    )
);

named!(
    command<&str, Command>,
    switch!(
        peek!(is_not!(" \r")),
        "PASS" => call!(command_pass) |
        "NICK" => call!(command_nick) |
        "USER" => call!(command_user) |
        "SERVER" => call!(command_server) |
        "OPER" => call!(command_oper) |
        "QUIT" => call!(command_quit) |
        "SQUIT" => call!(command_squit) |
        "JOIN" => call!(command_join) |
        "PART" => call!(command_part) |
        "MODE" => call!(command_mode) |
        "TOPIC" => call!(command_topic) |
        "NAMES" => call!(command_names) |
        "LIST" => call!(command_list) |
        "INVITE" => call!(command_invite) |
        "KICK" => call!(command_kick) |
        "VERSION" => call!(command_version) |
        "STATS" => call!(command_stats) |
        "LINKS" => call!(command_links) |
        "TIME" => call!(command_time) |
        "CONNECT" => call!(command_connect) |
        "TRACE" => call!(command_trace) |
        "ADMIN" => call!(command_admin) |
        "INFO" => call!(command_info) |
        "PRIVMSG" => call!(command_privmsg) |
        "NOTICE" => call!(command_notice) |
        "WHO" => call!(command_who) |
        "WHOIS" => call!(command_whois) |
        "WHOWAS" => call!(command_whowas) |
        "KILL" => call!(command_kill) |
        "PING" => call!(command_ping) |
        "PONG" => call!(command_pong) |
        "ERROR" => call!(command_error) |
        "AWAY" => call!(command_away) |
        "REHASH" => call!(command_rehash) |
        "RESTART" => call!(command_restart) |
        "SUMMON" => call!(command_summon) |
        "USERS" => call!(command_users) |
        "WALLOPS" => call!(command_wallops) |
        "USERHOST" => call!(command_userhost) |
        "ISON" => call!(command_ison)
    )
);


#[derive(PartialEq, Eq, Debug)]
pub struct Message {
    prefix: Option<Prefix>,
    command: Command,
}

named!(
    pub message<&str, Message>,
    do_parse!(
        prefix: opt!(do_parse!(prefix: prefix >> spaces >> (prefix))) >>
        command: command >>
        tag!("\r\n") >>
        (Message { prefix: prefix, command: command })
    )
);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass() {
        assert_eq!(command_pass("PASS password\r\n"),
                   Ok(("\r\n", Command::Pass { password: "password".into() })));
        assert_eq!(command_pass("PASS :password\r\n"),
                   Ok(("\r\n", Command::Pass { password: "password".into() })));

        assert_eq!(command_pass("PASS  password\r\n"),
                   Ok(("\r\n", Command::Pass { password: "password".into() })));
        assert_eq!(command_pass("PASS  :password\r\n"),
                   Ok(("\r\n", Command::Pass { password: "password".into() })));
    }

    #[test]
    fn nick() {
        assert_eq!(command_nick("NICK nickname\r\n"),
                   Ok(("\r\n", Command::Nick { nickname: "nickname".into(), hopcount: None })));
        assert_eq!(command_nick("NICK :nickname\r\n"),
                   Ok(("\r\n", Command::Nick { nickname: "nickname".into(), hopcount: None })));

        assert_eq!(command_nick("NICK  nickname  42\r\n"),
                   Ok(("\r\n", Command::Nick { nickname: "nickname".into(), hopcount: Some(42) })));
        assert_eq!(command_nick("NICK nickname :42\r\n"),
                   Ok(("\r\n", Command::Nick { nickname: "nickname".into(), hopcount: Some(42) })));

    }

    #[test]
    fn user() {
        assert_eq!(command_user("USER user host server real\r\n"),
                   Ok(("\r\n", Command::User { username: "user".to_string(),
                                               hostname: "host".to_string(),
                                               servername: "server".to_string(),
                                               realname: "real".to_string() })));

        assert_eq!(command_user("USER user  host   server    :real name\r\n"),
                   Ok(("\r\n", Command::User { username: "user".to_string(),
                                               hostname: "host".to_string(),
                                               servername: "server".to_string(),
                                               realname: "real name".to_string() })));
    }

    #[test]
    fn server() {
        assert_eq!(command_server("SERVER foo 5 something\r\n"),
                   Ok(("\r\n", Command::Server { servername: "foo".to_string(),
                                                 hopcount: 5,
                                                 info: "something".to_string() })));
        assert_eq!(command_server("SERVER foo    5  :this is some server!\r\n"),
                   Ok(("\r\n", Command::Server { servername: "foo".to_string(),
                                                 hopcount: 5,
                                                 info: "this is some server!".to_string() })));
    }

    #[test]
    fn oper() {
        assert_eq!(command_oper("OPER user pass\r\n"),
                   Ok(("\r\n", Command::Oper { user: "user".to_string(),
                                               password: "pass".to_string() })));
        assert_eq!(command_oper("OPER user  :pass\r\n"),
                   Ok(("\r\n", Command::Oper { user: "user".to_string(),
                                               password: "pass".to_string() })));
    }

    #[test]
    fn quit() {
        assert_eq!(command_quit("QUIT\r\n"),
                   Ok(("\r\n", Command::Quit { message: None })));
        assert_eq!(command_quit("QUIT bye\r\n"),
                   Ok(("\r\n", Command::Quit { message: Some("bye".to_string()) })));
        assert_eq!(command_quit("QUIT  :good bye\r\n"),
                   Ok(("\r\n", Command::Quit { message: Some("good bye".to_string()) })));
    }

    #[test]
    fn squit() {
        assert_eq!(command_squit("SQUIT server comment\r\n"),
                   Ok(("\r\n", Command::Squit { server: "server".to_string(),
                                                comment: "comment".to_string() })));
        assert_eq!(command_squit("SQUIT server  :comment\r\n"),
                   Ok(("\r\n", Command::Squit { server: "server".to_string(),
                                                comment: "comment".to_string() })));
    }

    #[test]
    fn join() {
        assert_eq!(command_join("JOIN #foo\r\n"),
                   Ok(("\r\n", Command::Join { channels: vec!["#foo".to_string()],
                                               keys: vec![] })));
        assert_eq!(command_join("JOIN #foo,#bar\r\n"),
                   Ok(("\r\n", Command::Join { channels: vec!["#foo".to_string(),
                                                              "#bar".to_string()],
                                               keys: vec![] })));
        assert_eq!(command_join("JOIN #foo,#bar  baz,quux\r\n"),
                   Ok(("\r\n", Command::Join { channels: vec!["#foo".to_string(),
                                                              "#bar".to_string()],
                                               keys: vec!["baz".to_string(),
                                                          "quux".to_string()] })));
    }

    #[test]
    fn part() {
        assert_eq!(command_part("PART #foo\r\n"),
                   Ok(("\r\n", Command::Part { channels: vec!["#foo".to_string()] })));
        assert_eq!(command_part("PART  #foo,#bar\r\n"),
                   Ok(("\r\n", Command::Part { channels: vec!["#foo".to_string(),
                                                              "#bar".to_string()] })));
    }

    #[test]
    fn topic() {
        assert_eq!(command_topic("TOPIC #channel\r\n"),
                   Ok(("\r\n", Command::Topic { channel: "#channel".to_string(),
                                                topic: None })));
        assert_eq!(command_topic("TOPIC #channel something\r\n"),
                   Ok(("\r\n", Command::Topic { channel: "#channel".to_string(),
                                                topic: Some("something".to_string()) })));
        assert_eq!(command_topic("TOPIC #channel  :something else\r\n"),
                   Ok(("\r\n", Command::Topic { channel: "#channel".to_string(),
                                                topic: Some("something else".to_string()) })));
    }

    #[test]
    fn test_prefix() {
        assert_eq!(
            prefix(":foo.bar PRIVMSG #baz :quux"),
            Ok((" PRIVMSG #baz :quux", Prefix("foo.bar".to_string())))
        );
    }

    #[test]
    fn test_argument_middle() {
        assert_eq!(
            argument_middle("foo :baz"),
            Ok((" :baz", "foo"))
        );
    }

    #[test]
    fn test_argument_middle_initial_colon_not_allowed() {
        assert_eq!(
            argument_middle(":foo baz"),
            Err(nom::Err::Error(nom::Context::Code(":foo baz", nom::ErrorKind::Verify)))
        );
    }

    #[test]
    fn test_argument_trailing() {
        assert_eq!(
            argument_trailing(":foo bar baz\r\n"),
            Ok(("\r\n", "foo bar baz"))
        );
    }

    #[test]
    fn test_argument_trailing_empty() {
        assert_eq!(
            argument_trailing(":\r\n"),
            Ok(("\r\n", ""))
        );
    }

    #[test]
    fn test_command_privmsg() {
        assert_eq!(
            command_privmsg("PRIVMSG #foo,#bar baz\r\n"),
            Ok(("\r\n", Command::Privmsg { receivers: vec!["#foo".to_string() ,"#bar".to_string()], message: "baz".to_string() }))
        );

        assert_eq!(
            command_privmsg("PRIVMSG #foo,#bar :baz quux\r\n"),
            Ok(("\r\n", Command::Privmsg { receivers: vec!["#foo".to_string(), "#bar".to_string()], message: "baz quux".to_string() }))
        );
    }

    #[test]
    fn test_message() {
        println!("{:?}", message(":irc.example.org PRIVMSG #foo :bar baz\r\n"));
        assert_eq!(
            message(":irc.example.org PRIVMSG #foo :bar baz\r\n"),
            Ok(("", Message { prefix: Some(Prefix("irc.example.org".to_string())), command: Command::Privmsg { receivers: vec!["#foo".into()], message: "bar baz".into() }}))
        );
    }

    #[test]
    fn test_whois() {
        assert_eq!(message("WHO kyrias\r\n"),
                   Ok(("", Message { prefix: None, command: Command::Who { name: None, o: Some("kyrias".into()) }})));
        assert_eq!(message("WHO kyrias foo\r\n"),
                   Ok(("", Message { prefix: None, command: Command::Who { name: Some("kyrias".into()), o: Some("foo".into()) }})));
        assert_eq!(message("WHOIS kyrias\r\n"),
                   Ok(("", Message { prefix: None, command: Command::Whois { server: None, nickmasks: vec!["kyrias".into()] }})));
        assert_eq!(message("WHOIS kyrias,demize\r\n"),
                   Ok(("", Message { prefix: None, command: Command::Whois { server: None, nickmasks: vec!["kyrias".into(), "demize".into()] }})));
        assert_eq!(message("WHOIS chat.freenode.net kyrias,demize\r\n"),
                   Ok(("", Message { prefix: None, command: Command::Whois { server: Some("chat.freenode.net".into()), nickmasks: vec!["kyrias".into(), "demize".into()] }})));
    }
}
