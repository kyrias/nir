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

    Privmsg { receiver: String, message: String },
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
        hopcount: opt!(argument_last) >>
        (Command::Nick { nickname: nickname.to_string(), hopcount: hopcount.and_then(|hc| Some(hc.to_string())) })
    )
);

named!(
    command_privmsg<&str, Command>,
    do_parse!(
        tag!("PRIVMSG") >>
        tag!(" ") >>
        receiver: argument_middle >>
        tag!(" ") >>
        message: argument_last >>
        (Command::Privmsg { receiver: receiver.to_string(), message: message.to_string() })
    )
);

named!(
    command<&str, Command>,
    alt!(
        command_pass |
        command_nick |

        command_privmsg
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
            Ok(("\r\n", Command::Privmsg { receiver: "#foo,#bar".to_string(), message: "baz".to_string() }))
        );

        assert_eq!(
            command_privmsg("PRIVMSG #foo,#bar :baz quux\r\n"),
            Ok(("\r\n", Command::Privmsg { receiver: "#foo,#bar".to_string(), message: "baz quux".to_string() }))
        );
    }

    #[test]
    fn test_message() {
        println!("{:?}", message(":irc.example.org PRIVMSG #foo :bar baz\r\n"));
        assert_eq!(
            message(":irc.example.org PRIVMSG #foo :bar baz\r\n"),
            Ok(("", Message { prefix: Some(Prefix("irc.example.org".to_string())), command: Command::Privmsg { receiver: "#foo".into(), message: "bar baz".into() }}))
        );
    }
}
