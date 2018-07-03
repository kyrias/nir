#[macro_use]
extern crate nom;


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
        peek!(verify!(nom::anychar, |val:char| val != ':')) >>
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
    argument_last<&str, &str>,
    alt!(
        argument_middle |
        argument_trailing
    )
);


// Command parsers
#[derive(PartialEq, Eq, Debug)]
pub enum Command {
    Pass { password: String },
    Nick { nickname: String, hopcount: Option<String> },
    User { username: String, hostname: String, servername: String, realname: String },
    Server { servername: String, hopcount: String, info: String },
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
        tag!(" ") >>
        password: argument_last >>
        (Command::Pass { password: password.to_string() })
    )
);

named!(
    command_nick<&str, Command>,
    do_parse!(
        tag!("NICK") >>
        tag!(" ") >>
        nickname: argument_middle >>
        opt!(tag!(" ")) >>
        hopcount: opt!(argument_last) >>
        (Command::Nick { nickname: nickname.to_string(), hopcount: hopcount.map(|hc| hc.to_string()) })
    )
);

named!(
    command_user<&str, Command>,
    do_parse!(
        tag!("USER") >>
        tag!(" ") >>
        username: argument_middle >>
        tag!(" ") >>
        hostname: argument_middle >>
        tag!(" ") >>
        servername: argument_middle >>
        tag!(" ") >>
        realname: argument_last >>
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
        tag!(" ") >>
        servername: argument_middle >>
        tag!(" ") >>
        hopcount: argument_middle >>
        tag!(" ") >>
        info: argument_last >>
        (Command::Server { servername: servername.to_string(), hopcount: hopcount.to_string(), info: info.to_string() })
    )
);

named!(
    command_oper<&str, Command>,
    do_parse!(
        tag!("OPER") >>
        tag!(" ") >>
        user: argument_middle >>
        tag!(" ") >>
        password: argument_last >>
        (Command::Oper { user: user.to_string(), password: password.to_string() })
    )
);

named!(
    command_quit<&str, Command>,
    do_parse!(
        tag!("QUIT") >>
        opt!(tag!(" ")) >>
        message: opt!(argument_last) >>
        (Command::Quit { message: message.map(|m| m.to_string()) })
    )
);

named!(
    command_squit<&str, Command>,
    do_parse!(
        tag!("SQUIT ") >>
        server: argument_middle >>
        tag!(" ") >>
        comment: argument_last >>
        (Command::Squit { server: server.to_string(), comment: comment.to_string() })
    )
);

named!(
    command_join<&str, Command>,
    do_parse!(
        tag!("JOIN ") >>
        channels: argument_last >>
        opt!(tag!(" ")) >>
        keys: opt!(argument_last) >>
        (Command::Join { channels: channels.split(",").map(|c| c.to_string()).collect(),
                         keys: keys.map(|ks| ks.split(",").map(|k| k.to_string()).collect())
                                   .unwrap_or_else(|| Vec::new())})
    )
);

named!(
    command_part<&str, Command>,
    do_parse!(
        tag!("PART ") >>
        channels: argument_last >>
        (Command::Part { channels: channels.split(",").map(|c| c.to_string()).collect() })
    )
);

named!(
    command_mode<&str, Command>,
    do_parse!(
        tag!("MODE ") >>
        target: argument_middle >>
        tag!(" ") >>
        modes: argument_middle >>
        opt!(tag!(" ")) >>
        limit: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        user: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        banmask: opt!(argument_last) >>
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
        tag!("TOPIC ") >>
        channel: argument_middle >>
        opt!(tag!(" ")) >>
        topic: opt!(argument_last) >>
        (Command::Topic { channel: channel.to_string(), topic: topic.map(|t| t.to_string()) })
    )
);

named!(
    command_names<&str, Command>,
    do_parse!(
        tag!("NAMES") >>
        opt!(tag!(" ")) >>
        channels: opt!(argument_last) >>
        (Command::Names { channels: channels.map(|cs| cs.split(",").map(|c| c.to_string()).collect())
                                            .unwrap_or_else(|| Vec::new()) })
    )
);

named!(
    command_list<&str, Command>,
    do_parse!(
        tag!("LIST") >>
        opt!(tag!(" ")) >>
        channels: opt!(argument_middle) >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::List { channels: channels.map(|cs| cs.split(",").map(|c| c.to_string()).collect())
                                           .unwrap_or_else(|| Vec::new()),
                         server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_invite<&str, Command>,
    do_parse!(
        tag!("INVITE") >>
        tag!(" ") >>
        nickname: argument_middle >>
        tag!(" ") >>
        channel: argument_last >>
        (Command::Invite { nickname: nickname.to_string(), channel: channel.to_string() })
    )
);

named!(
    command_kick<&str, Command>,
    do_parse!(
        tag!("KICK") >>
        tag!(" ") >>
        channel: argument_middle >>
        tag!(" ") >>
        user: argument_last >>
        opt!(tag!(" ")) >>
        comment: opt!(argument_last) >>
        (Command::Kick { channel: channel.to_string(), user: user.to_string(), comment: comment.map(|c| c.to_string()) })
    )
);

named!(
    command_version<&str, Command>,
    do_parse!(
        tag!("VERSION") >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Version { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_stats<&str, Command>,
    do_parse!(
        tag!("STATS") >>
        opt!(tag!(" ")) >>
        query: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Stats { query: query.map(|q| q.to_string()), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_links_all_arguments<&str, Command>,
    do_parse!(
        tag!("LINKS") >>
        tag!(" ") >>
        remote_server: argument_middle >>
        tag!(" ") >>
        server_mask: argument_last >>
        (Command::Links { remote_server: Some(remote_server.to_string()), server_mask: Some(server_mask.to_string()) })
    )
);

named!(
    command_links_opt_server_mask<&str, Command>,
    do_parse!(
        tag!("LINKS") >>
        opt!(tag!(" ")) >>
        server_mask: opt!(argument_last) >>
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
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Time { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_connect<&str, Command>,
    do_parse!(
        tag!("CONNECT") >>
        tag!(" ") >>
        target_server: argument_last >>
        opt!(tag!(" ")) >>
        port: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        remote_server: opt!(argument_last) >>
        (Command::Connect { target_server: target_server.to_string(),
                            port: port.map(|p| p.to_string()),
                            remote_server: remote_server.map(|r| r.to_string()) })
    )
);

named!(
    command_trace<&str, Command>,
    do_parse!(
        tag!("TRACE") >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Trace { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_admin<&str, Command>,
    do_parse!(
        tag!("ADMIN") >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Admin { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_info<&str, Command>,
    do_parse!(
        tag!("INFO") >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Info { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_privmsg<&str, Command>,
    do_parse!(
        tag!("PRIVMSG") >>
        tag!(" ") >>
        receivers: argument_middle >>
        tag!(" ") >>
        message: argument_last >>
        (Command::Privmsg { receivers: receivers.split(",").map(|r| r.to_string()).collect(),
                            message: message.to_string() })
    )
);

named!(
    command_notice<&str, Command>,
    do_parse!(
        tag!("NOTICE") >>
        nickname: argument_middle >>
        tag!(" ") >>
        text: argument_last >>
        (Command::Notice { nickname: nickname.to_string(), text: text.to_string() })
    )
);

named!(
    command_who<&str, Command>,
    do_parse!(
        tag!("WHO") >>
        tag!(" ") >>
        name: opt!(
            do_parse!(
                name: argument_last >>
                tag!(" ") >>
                (name)
            )
        ) >>
        o: opt!(argument_last) >>
        (Command::Who { name: name.map(|n| n.to_string()), o: o.map(|o| o.to_string()) })
    )
);

named!(
    command_whois<&str, Command>,
    do_parse!(
        tag!("WHOIS") >>
        tag!(" ") >>
        server: opt!(
            do_parse!(
                server: argument_middle >>
                tag!(" ") >>
                (server)
            )
        ) >>
        nickmasks: argument_last >>
        (Command::Whois { server: server.map(|s| s.to_string()),
                          nickmasks: nickmasks.split(",").map(|n| n.to_string()).collect() })
    )
);

named!(
    command_whowas<&str, Command>,
    do_parse!(
        tag!("WHOWAS") >>
        tag!(" ") >>
        nickname: argument_last >>
        opt!(tag!(" ")) >>
        count: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Whowas { nickname: nickname.to_string(), count: count.map(|c| c.to_string()), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_kill<&str, Command>,
    do_parse!(
        tag!("KILL") >>
        tag!(" ") >>
        nickname: argument_middle >>
        tag!(" ") >>
        comment: argument_last >>
        (Command::Kill { nickname: nickname.to_string(), comment: comment.to_string() })
    )
);

named!(
    command_ping<&str, Command>,
    do_parse!(
        tag!("PING") >>
        tag!(" ") >>
        server1: argument_last >>
        opt!(tag!(" ")) >>
        server2: opt!(argument_last) >>
        (Command::Ping { server1: server1.to_string(), server2: server2.map(|s2| s2.to_string()) })
    )
);

named!(
    command_pong<&str, Command>,
    do_parse!(
        tag!("PONG") >>
        tag!(" ") >>
        daemon1: argument_last >>
        opt!(tag!(" ")) >>
        daemon2: opt!(argument_last) >>
        (Command::Pong { daemon1: daemon1.to_string(), daemon2: daemon2.map(|s2| s2.to_string()) })
    )
);

named!(
    command_error<&str, Command>,
    do_parse!(
        tag!("ERROR") >>
        tag!(" ") >>
        message: argument_last >>
        (Command::Error { message: message.to_string() })
    )
);

named!(
    command_away<&str, Command>,
    do_parse!(
        tag!("AWAY") >>
        message: opt!(
            do_parse!(
                tag!(" ") >>
                message: argument_last >>
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
        tag!(" ") >>
        user: argument_last >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Summon { user: user.to_string(), server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_users<&str, Command>,
    do_parse!(
        tag!("USERS") >>
        opt!(tag!(" ")) >>
        server: opt!(argument_last) >>
        (Command::Users { server: server.map(|s| s.to_string()) })
    )
);

named!(
    command_wallops<&str, Command>,
    do_parse!(
        tag!("WALLOPS") >>
        tag!(" ") >>
        text: argument_last >>
        (Command::Wallops { text: text.to_string() })
    )
);

named!(
    command_userhost<&str, Command>,
    do_parse!(
        tag!("USERHOST") >>
        tag!(" ") >>
        nick1: argument_last >>
        opt!(tag!(" ")) >>
        nick2: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        nick3: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        nick4: opt!(argument_last) >>
        opt!(tag!(" ")) >>
        nick5: opt!(argument_last) >>
        (Command::Userhost { nicknames: vec![Some(nick1), nick2, nick3, nick4, nick5].iter().flat_map(|n| n.map(|n| n.to_string())).collect() })
    )
);

named!(
    command_ison<&str, Command>,
    do_parse!(
        tag!("ISON") >>
        tag!(" ") >>
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
        prefix: opt!(do_parse!(prefix: prefix >> tag!(" ") >> (prefix))) >>
        command: command >>
        tag!("\r\n") >>
        (Message { prefix: prefix, command: command })
    )
);


#[cfg(test)]
mod tests {
    use super::*;

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
