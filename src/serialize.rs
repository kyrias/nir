use std::fmt::{self, Write};

use {AddedChannelMode, ChannelModeChange, Command, Message, Prefix, RemovedChannelMode};

pub trait Serialize {
    fn serialize<T>(&self, buf: &mut T) -> fmt::Result
    where
        T: Write;
}

impl Serialize for Prefix {
    fn serialize<T>(&self, buf: &mut T) -> fmt::Result
    where
        T: Write,
    {
        write!(buf, ":{}", self.0)?;
        Ok(())
    }
}

impl Serialize for Message {
    fn serialize<T>(&self, buf: &mut T) -> fmt::Result
    where
        T: Write,
    {
        if let Some(ref p) = self.prefix {
            p.serialize(buf)?;
            write!(buf, " ")?
        }
        self.command.serialize(buf)?;
        write!(buf, "\r\n")?;
        Ok(())
    }
}

impl Serialize for Vec<ChannelModeChange> {
    fn serialize<T>(&self, buf: &mut T) -> fmt::Result
    where
        T: Write,
    {
        let (added, removed): (Vec<_>, Vec<_>) = self
            .iter()
            .map(ChannelModeChange::to_tuple)
            .partition(|(action, _, _)| *action == '+');

        let mut added: (String, Vec<String>) = added.iter().fold(
            (String::new(), Vec::new()),
            |(mut modechars, mut values), (_, modechar, value)| {
                modechars.push(*modechar);
                if let Some(v) = value {
                    values.push(v.to_owned());
                }
                (modechars, values)
            },
        );

        let mut removed: (String, Vec<String>) = removed.iter().fold(
            (String::new(), Vec::new()),
            |(mut modechars, mut values), (_, modechar, value)| {
                modechars.push(*modechar);
                if let Some(v) = value {
                    values.push(v.to_owned());
                }
                (modechars, values)
            },
        );

        let mut out = String::new();
        let mut values: Vec<String> = Vec::new();

        if !added.0.is_empty() {
            write!(out, "+{}", added.0)?;
            values.append(&mut added.1);
        };
        if !removed.0.is_empty() {
            write!(out, "-{}", removed.0)?;
            values.append(&mut removed.1);
        };

        if !values.is_empty() {
            write!(out, " {}", values.join(" "))?;
        };

        if !out.is_empty() {
            write!(buf, " {}", out)?;
        };

        Ok(())
    }
}

impl Serialize for Command {
    fn serialize<T>(&self, buf: &mut T) -> fmt::Result
    where
        T: Write,
    {
        match *self {
            Command::Pass { ref password } => {
                write!(buf, "PASS :{}", password)?;
                Ok(())
            }
            Command::Nick {
                ref nickname,
                ref hopcount,
            } => {
                write!(buf, "NICK {}", nickname)?;
                if let Some(hc) = hopcount {
                    write!(buf, " {}", hc)?;
                };
                Ok(())
            }
            Command::User {
                ref username,
                ref hostname,
                ref servername,
                ref realname,
            } => {
                write!(
                    buf,
                    "USER {} {} {} :{}",
                    username, hostname, servername, realname
                )?;
                Ok(())
            }
            Command::Server {
                ref servername,
                ref hopcount,
                ref info,
            } => {
                write!(buf, "SERVER {} {} :{}", servername, hopcount, info)?;
                Ok(())
            }
            Command::Oper {
                ref user,
                ref password,
            } => {
                write!(buf, "OPER {} :{}", user, password)?;
                Ok(())
            }
            Command::Quit { ref message } => {
                write!(buf, "QUIT")?;
                if let Some(m) = message {
                    write!(buf, " :{}", m)?;
                };
                Ok(())
            }
            Command::Squit {
                ref server,
                ref comment,
            } => {
                write!(buf, "SQUIT {} :{}", server, comment)?;
                Ok(())
            }
            Command::Join {
                ref channels,
                ref keys,
            } => {
                let channels = channels.join(",");
                let keys = keys.join(",");
                write!(buf, "JOIN {} :{}", channels, keys)?;
                Ok(())
            }
            Command::Part { ref channels } => {
                write!(buf, "PART {}", channels.join(","))?;
                Ok(())
            }
            Command::Mode {
                ref target,
                ref modechanges,
            } => {
                write!(buf, "MODE {}", target)?;
                if let Some(mcs) = modechanges {
                    mcs.serialize(buf)?;
                };
                Ok(())
            }
            Command::Topic {
                ref channel,
                ref topic,
            } => {
                write!(buf, "TOPIC {}", channel)?;
                if let Some(t) = topic {
                    write!(buf, " :{}", t)?;
                }
                Ok(())
            }
            Command::Names { ref channels } => {
                write!(buf, "NAMES {}", channels.join(","))?;
                Ok(())
            }
            Command::List {
                ref channels,
                ref server,
            } => {
                write!(buf, "LIST")?;
                let channels = channels.join(",");
                if !channels.is_empty() {
                    write!(buf, " {}", channels)?;
                };
                if let Some(s) = server {
                    write!(buf, " :{}", s)?;
                };
                Ok(())
            }
            Command::Invite {
                ref nickname,
                ref channel,
            } => {
                write!(buf, "INVITE {} {}", nickname, channel)?;
                Ok(())
            }
            Command::Kick {
                ref channel,
                ref user,
                ref comment,
            } => {
                write!(buf, "KICK {} {}", channel, user)?;
                if let Some(c) = comment {
                    write!(buf, " :{}", c)?;
                };
                Ok(())
            }
            Command::Version { ref server } => {
                write!(buf, "VERSION")?;
                if let Some(s) = server {
                    write!(buf, " {}", s)?;
                };
                Ok(())
            }
            Command::Stats {
                ref query,
                ref server,
            } => {
                write!(buf, "STATS")?;
                if let Some(q) = query {
                    write!(buf, " {}", q)?;
                };
                if let Some(s) = server {
                    write!(buf, " {}", s)?;
                };
                Ok(())
            }
            Command::Links {
                ref remote_server,
                ref server_mask,
            } => {
                write!(buf, "LINKS")?;
                if let Some(rs) = remote_server {
                    write!(buf, " {}", rs)?;
                };
                if let Some(sm) = server_mask {
                    write!(buf, " {}", sm)?;
                };
                Ok(())
            }
            Command::Time { ref server } => {
                write!(buf, "TIME")?;
                if let Some(s) = server {
                    write!(buf, " {}", s)?;
                }
                Ok(())
            }
            Command::Connect {
                ref target_server,
                ref port,
                ref remote_server,
            } => {
                write!(buf, "CONNECT {}", target_server)?;
                if let Some(port) = port {
                    write!(buf, " {}", port)?;
                }
                if let Some(rs) = remote_server {
                    write!(buf, " {}", rs)?;
                }
                Ok(())
            }
            Command::Trace { ref server } => {
                write!(buf, "TRACE")?;
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                }
                Ok(())
            }
            Command::Admin { ref server } => {
                write!(buf, "ADMIN")?;
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                };
                Ok(())
            }
            Command::Info { ref server } => {
                write!(buf, "INFO")?;
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                };
                Ok(())
            }
            Command::Privmsg {
                ref receivers,
                ref message,
            } => {
                write!(buf, "PRIVMSG {} :{}", receivers.join(","), message)?;
                Ok(())
            }
            Command::Notice {
                ref nickname,
                ref text,
            } => {
                write!(buf, "NOTICE {} :{}", nickname, text)?;
                Ok(())
            }
            Command::Who { ref name, ref o } => {
                write!(buf, "WHO")?;
                if let Some(name) = name {
                    write!(buf, " {}", name)?;
                }
                if let Some(o) = o {
                    write!(buf, " {}", o)?;
                }
                Ok(())
            }
            Command::Whois {
                ref server,
                ref nickmasks,
            } => {
                write!(buf, "WHOIS")?;
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                }
                write!(buf, " {}", nickmasks.join(","))?;
                Ok(())
            }
            Command::Whowas {
                ref nickname,
                ref count,
                ref server,
            } => {
                write!(buf, "WHOWAS {}", nickname)?;
                if let Some(count) = count {
                    write!(buf, " {}", count)?;
                };
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                };
                Ok(())
            }
            Command::Kill {
                ref nickname,
                ref comment,
            } => {
                write!(buf, "KILL {} :{}", nickname, comment)?;
                Ok(())
            }
            Command::Ping {
                ref server1,
                ref server2,
            } => {
                write!(buf, "PING {}", server1)?;
                if let Some(server2) = server2 {
                    write!(buf, " {}", server2)?;
                }
                Ok(())
            }
            Command::Pong {
                ref daemon1,
                ref daemon2,
            } => {
                write!(buf, "PONG {}", daemon1)?;
                if let Some(daemon2) = daemon2 {
                    write!(buf, " {}", daemon2)?;
                };
                Ok(())
            }
            Command::Error { ref message } => {
                write!(buf, "ERROR :{}", message)?;
                Ok(())
            }
            Command::Away { ref message } => {
                write!(buf, "AWAY")?;
                if let Some(message) = message {
                    write!(buf, " :{}", message)?;
                };
                Ok(())
            }
            Command::Rehash => {
                write!(buf, "REHASH")?;
                Ok(())
            }
            Command::Restart => {
                write!(buf, "RESTART")?;
                Ok(())
            }
            Command::Summon {
                ref user,
                ref server,
            } => {
                write!(buf, "SUMMON {}", user)?;
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                };
                Ok(())
            }
            Command::Users { ref server } => {
                write!(buf, "USERS")?;
                if let Some(server) = server {
                    write!(buf, " {}", server)?;
                }
                Ok(())
            }
            Command::Wallops { ref text } => {
                write!(buf, "WALLOPS :{}", text)?;
                Ok(())
            }
            Command::Userhost { ref nicknames } => {
                write!(buf, "USERHOST {}", nicknames.join(" "))?;
                Ok(())
            }
            Command::Ison { ref nicknames } => {
                write!(buf, "ISON")?;
                for nick in nicknames {
                    write!(buf, " {}", nick)?;
                }
                Ok(())
            }
        }
    }
}

impl AddedChannelMode {
    pub(crate) fn to_tuple(&self) -> (char, Option<String>) {
        match *self {
            AddedChannelMode::Op(ref target) => ('o', Some(target.to_owned())),
            AddedChannelMode::Voice(ref target) => ('v', Some(target.to_owned())),
            AddedChannelMode::InviteOnly => ('i', None),
            AddedChannelMode::Moderated => ('m', None),
            AddedChannelMode::NoExternal => ('n', None),
            AddedChannelMode::Quiet(ref target) => ('q', Some(target.to_owned())),
            AddedChannelMode::Private => ('p', None),
            AddedChannelMode::Secret => ('s', None),
            AddedChannelMode::OpsTopic => ('t', None),
            AddedChannelMode::Key(ref key) => ('k', Some(key.to_owned())),
            AddedChannelMode::Limit(ref limit) => ('l', Some(limit.to_string())),
            AddedChannelMode::Ban(ref target) => ('b', Some(target.to_owned())),
            AddedChannelMode::BanException(ref target) => ('e', Some(target.to_owned())),
            AddedChannelMode::InviteException(ref target) => ('I', Some(target.to_owned())),
        }
    }
}

impl RemovedChannelMode {
    fn to_tuple(&self) -> (char, Option<String>) {
        match *self {
            RemovedChannelMode::Op(ref target) => ('o', Some(target.to_owned())),
            RemovedChannelMode::Voice(ref target) => ('v', Some(target.to_owned())),
            RemovedChannelMode::InviteOnly => ('i', None),
            RemovedChannelMode::Moderated => ('m', None),
            RemovedChannelMode::NoExternal => ('n', None),
            RemovedChannelMode::Quiet(ref target) => ('q', Some(target.to_owned())),
            RemovedChannelMode::Private => ('p', None),
            RemovedChannelMode::Secret => ('s', None),
            RemovedChannelMode::OpsTopic => ('t', None),
            RemovedChannelMode::Key => ('k', None),
            RemovedChannelMode::Limit => ('l', None),
            RemovedChannelMode::Ban(ref target) => ('b', Some(target.to_owned())),
            RemovedChannelMode::BanException(ref target) => ('e', Some(target.to_owned())),
            RemovedChannelMode::InviteException(ref target) => ('I', Some(target.to_owned())),
        }
    }
}

impl ChannelModeChange {
    pub(crate) fn to_tuple(&self) -> (char, char, Option<String>) {
        match *self {
            ChannelModeChange::Added(ref mc) => {
                let (modechar, value) = mc.to_tuple();
                ('+', modechar, value)
            }
            ChannelModeChange::Removed(ref mc) => {
                let (modechar, value) = mc.to_tuple();
                ('-', modechar, value)
            }
        }
    }
}
