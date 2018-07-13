use nom;

use ::argument_maybe_last;

/// Channel modes: https://tools.ietf.org/html/rfc2811#section-4

///
/// VALUELESS
///

#[derive(Debug)]
enum ValueLessChannelMode {
    Op,
    Voice,

    //Anonymous,
    InviteOnly,
    Moderated,
    NoExternal,
    Quiet,
    Private,
    Secret,
    //Reop,
    OpsTopic,

    Key,
    Limit,

    Ban,
    BanException,
    InviteException,
}

impl ValueLessChannelMode {
    fn parse(input: &str) -> nom::IResult<&str, ValueLessChannelMode> {
        let (remaining, c) = try_parse!(input, nom::anychar);
        let vlm = match c {
        'o' => ValueLessChannelMode::Op,
        'v' => ValueLessChannelMode::Voice,

        'i' => ValueLessChannelMode::InviteOnly,
        'm' => ValueLessChannelMode::Moderated,
        'n' => ValueLessChannelMode::NoExternal,
        'q' => ValueLessChannelMode::Quiet,
        'p' => ValueLessChannelMode::Private,
        's' => ValueLessChannelMode::Secret,
        't' => ValueLessChannelMode::OpsTopic,

        'k' => ValueLessChannelMode::Key,
        'l' => ValueLessChannelMode::Limit,

        'b' => ValueLessChannelMode::Ban,
        'e' => ValueLessChannelMode::BanException,
        'I' => ValueLessChannelMode::InviteException,
        _ => Err(nom::Err::Error(nom::Context::Code(input, nom::ErrorKind::Custom(1))))?,
        };
        Ok((remaining, vlm))
    }
}


#[derive(Debug)]
enum ValueLessChannelModeChange {
    Added(ValueLessChannelMode),
    Removed(ValueLessChannelMode),
}

impl ValueLessChannelModeChange {
    fn partial(input: &str) -> nom::IResult<&str, Vec<ValueLessChannelModeChange>> {
        let (remaining, status) = try_parse!(input, one_of!("+-"));
        match status {
            '+' => {
                let (remaining, modes) = try_parse!(remaining, many1!(ValueLessChannelMode::parse));
                let vlmcs = modes.into_iter().map(|m| ValueLessChannelModeChange::Added(m)).collect();
                Ok((remaining, vlmcs))
            },
            '-' => {
                let (remaining, modes) = try_parse!(remaining, many1!(ValueLessChannelMode::parse));
                let vlmcs = modes.into_iter().map(|m| ValueLessChannelModeChange::Removed(m)).collect();
                Ok((remaining, vlmcs))
            },
            _ => Err(nom::Err::Error(nom::Context::Code(input, nom::ErrorKind::Custom(2))))?,
        }
    }

    fn parse(input: &str) -> nom::IResult<&str, Vec<ValueLessChannelModeChange>> {
        let (remaining, vlmcs) = try_parse!(input, many1!(ValueLessChannelModeChange::partial));
        Ok((remaining, vlmcs.into_iter().flat_map(|mcp| mcp).collect()))
    }
}



///
/// VALUED
///

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ChannelMode {
    Op(String),
    Voice(String),

    InviteOnly,
    Moderated,
    NoExternal,
    Quiet(String),
    Private,
    Secret,
    OpsTopic,

    Key(String),
    Limit(u64),

    Ban(String),
    BanException(String),
    InviteException(String),
}

impl ChannelMode {
    fn from_valueless(input: &str, vlm: ValueLessChannelMode) -> nom::IResult<&str, ChannelMode> {
        named!(mode_argument<&str, &str>,
           do_parse!(
               tag!(" ") >>
               arg: argument_maybe_last >>
               (arg)
           )
        );

        match vlm {
            ValueLessChannelMode::Op => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::Op(arg.to_string())))
            },
            ValueLessChannelMode::Voice => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::Voice(arg.to_string())))
            },

            ValueLessChannelMode::InviteOnly => Ok((input, ChannelMode::InviteOnly)),
            ValueLessChannelMode::Moderated => Ok((input, ChannelMode::Moderated)),
            ValueLessChannelMode::NoExternal => Ok((input, ChannelMode::NoExternal)),
            ValueLessChannelMode::Quiet => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::Quiet(arg.to_string())))
            },
            ValueLessChannelMode::Private => Ok((input, ChannelMode::Private)),
            ValueLessChannelMode::Secret => Ok((input, ChannelMode::Secret)),
            ValueLessChannelMode::OpsTopic => Ok((input, ChannelMode::OpsTopic)),

            ValueLessChannelMode::Key => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::Key(arg.to_string())))
            },
            ValueLessChannelMode::Limit => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::Limit(u64::from_str_radix(arg, 10).expect("user limit"))))
            },

            ValueLessChannelMode::Ban => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::Ban(arg.to_string())))
            },
            ValueLessChannelMode::BanException => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::BanException(arg.to_string())))
            },
            ValueLessChannelMode::InviteException => {
                let (remaining, arg) = mode_argument(input)?;
                Ok((remaining, ChannelMode::InviteException(arg.to_string())))
            },
        }
    }
}


#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ChannelModeChange {
    Added(ChannelMode),
    Removed(ChannelMode),
}

impl ChannelModeChange {
    fn from_valueless(input: &str, mcp: ValueLessChannelModeChange) -> nom::IResult<&str, ChannelModeChange> {
        match mcp {
            ValueLessChannelModeChange::Added(mp) => {
                let (remaining, m) = ChannelMode::from_valueless(input, mp)?;
                Ok((remaining, ChannelModeChange::Added(m)))
            },
            ValueLessChannelModeChange::Removed(mp) => {
                let (remaining, m) = ChannelMode::from_valueless(input, mp)?;
                Ok((remaining, ChannelModeChange::Removed(m)))
            },
        }
    }
}

pub(crate) fn channel_modes(input: &str) -> nom::IResult<&str, Vec<ChannelModeChange>> {
    let mut output = Vec::new();
    let (mut remaining, mcps) = ValueLessChannelModeChange::parse(input)?;
    for mcp in mcps {
        let res = ChannelModeChange::from_valueless(remaining, mcp);
        let res = res?;
        remaining = res.0;
        output.push(res.1);
    }
    Ok((remaining, output))
}
