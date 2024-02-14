# pickpocket

A small learning project for DLL injection and code detours using Rust. I wrote this to help reverse engineering packets
to be used in [my server emulator](https://github.com/kumpelblase2/skrillax) for Silkroad Online.

Most loaders for Silkroad Online still work today, but some features do not, because they rely on specific function
offsets. As those offsets change from version to version, an updated version of a loader would need to be compiled in
order for those features to start working again. Unfortunately, I don't use a Windows machine and thus can't easily
recompile the existing loaders with those small adjustments. However, these loaders are quite small and thus should be
easy to implement, which is what this project is - an implementation of 'edxAnalyzer' in Rust for current iSro.

This currently builds using the `i686-pc-windows-gnu` because I couldn't get the `-msvc` target to work in my GNU
environment, but it should probably work with that as well. The program is expected to be run from within a wine prefix
using the built `pick.exe`. If you place both the `pick.exe` and `pocket.dll` into the Silkroad Online directory, you
should not need to pass any arguments. If you have different paths, you can specify them as `--silkroad` and `--dll`.

## Implementation state

The current state is essentially the minimum state for it to be useful to me - it pretty-prints the packets it
encounters according to what the client tried to read/write. For the most part, at least. There are still some issues
with it:

- The client appears to be using some slightly different functions for interacting with the gateway server (probably due
  to being encrypted). This isn't important to me right now.
- Massive Packets (Opcode 0x600D) are not pretty-printed. They're probably parsed again somewhere else. This is also not
  important to me right now.
- Hiding the Advert after closing worked initially but seem to be broken now. Would be nice if I got it to work again,
  but it's not really high priority.

Some things I might want to explore, but haven't felt the need to:

- Use memory scanning to figure out the right offsets automatically. Currently, they're predefined, but externally
  adjustable. To me that seems like a step forward compared to old implementations and is enough for me.
- Find a way to properly handle client crashes. The client is really easy to crash if it gets data it is not expecting,
  which also means the pretty-printing might not get the right information at the end of the day.

## Running

Simply run `pick.exe` from inside the Silkroad Online directory and it should start the game. It will then create a
file `packets.txt` where it will append all packets it has encountered. If you have it placed somewhere else or want to
adjust things, there are a few options available:

```
Usage: pick.exe [OPTIONS]

Options:
  --silkroad <SILKROAD>
      Specify the location of the `sro_client.exe` executable
  --dll <DLL>
      Specify the location of the `pocket.dll` library
  --no-skip-ad
      Do not skip the advertisement after the client closes.
  --send-address <SEND_ADDRESS>
      Specify the address for the packet send function. Currently unused.
  --write-address <WRITE_ADDRESS>
      Specify the address for the data write function.
  --opcode-address <OPCODE_ADDRESS>
      Specify the address for the packet enqueuing function, which is run to setup a packet as well as sending one.
  --read-address <READ_ADDRESS>
      Specify the address for the data reading function.
  --accept-address <ACCEPT_ADDRESS>
      Specify the address for the packet accepting/handling function.
  --skip-ad-address <SKIP_AD_ADDRESS>
      Specify the address for the function opening the advertisement window.
  -h, --help
          Print help
```

The current default offsets are valid for Version 1.594 of the game. They *might* still work for a later version of the
game, but it's quite possible that the offsets won't be valid anymore for newer versions. If the functions themselves
didn't change, it should be enough to pass the new offsets using the varying `-adress` options (`--write-address`,
`--opcode-address`).

## Building

As mentioned, this is currently set up to use the `i686-pc-windows-gnu` target. Under Linux, you can compile this easily
using [`cross`](https://github.com/cross-rs/cross) and simply run `cross build`. Under Windows, you should probably be
fine building with the default windows target: `cargo build --target i686-pc-windows-mvsc`. Note: we still want to build
for 32bit given Silkroad is a 32bit executable. In either case, you should end up with a `pick.exe` and a `pocket.dll`.
Also note, that we need to use `nightly` for some unstable features in our dependencies.