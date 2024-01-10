Rust Manta
==========

# This branch is work-in-progress functionality is incomplete, interfaces are likely to change.

# TODO
- client has to be mutable because of the ssh auth socket, need a way to address this

----

Really simple manta logic in rust

Example
-------

Simple

    $ ./mls /bahamas10/stor/foo
    a
    b
    dir/
    $ ./mls /bahamas10/stor/foo/dir
    hi
    $ ./mls /Joyent_Dev/public/SmartOS | tail
    20180802T002654Z/
    hotpatches/
    latest
    latest.html
    platform-latest.tgz
    smartos-latest-USB.img.bz2
    smartos-latest.iso
    smartos-latest.vmwarevm.tar.bz2
    smartos.html
    smartos.html.20150123-1635
    $ file mls
    mls:            ELF 64-bit LSB executable AMD64 Version 1, dynamically linked, not stripped

Excess Logging

    $ cargo run /bahamas10/stor/foo
	Finished dev [unoptimized + debuginfo] target(s) in 0.04s
	 Running `target/debug/rust-manta /stor/foo`
    "/stor/foo"
    ssh_auth_sock = /tmp/ssh-XXXXbdaq4N/agent.81672
    manta_key_id = e4:e3:97:89:62:eb:35:91:90:f9:5a:97:bb:35:50:72
    UnixStream { fd: 3, local: (unnamed), peer: "/tmp/ssh-XXXXbdaq4N/agent.81672" (pathname) }
    -- found 2 keys in ssh-agent --
    ssh-rsa SHA256:DTt4MACbRj4K7TFBvfr0wP0QqZt+i5/8k40Ky/aBo38= id_rsa
    ssh-rsa SHA256:q2f9rM7M7PzVV4o67x73zkW2HuH82lgATRzeuQt160Y= joyent_key

    curl -sS --header 'date: Sat, 04 Aug 2018 17:07:48 GMT' --header 'authorization: Signature keyId="/bahamas10/keys/e4:e3:97:89:62:eb:35:91:90:f9:5a:97:bb:35:50:72",algorithm="rsa-sha1",headers="date",signature="..."' 'https://us-east.manta.joyent.com/bahamas10/stor/foo';echo

    a
    b
    dir/
    $ cargo run /bahamas10/stor/foo/dir
	Finished dev [unoptimized + debuginfo] target(s) in 0.04s
	 Running `target/debug/rust-manta /stor/foo/dir`
    "/stor/foo/dir"
    ssh_auth_sock = /tmp/ssh-XXXXbdaq4N/agent.81672
    manta_key_id = e4:e3:97:89:62:eb:35:91:90:f9:5a:97:bb:35:50:72
    UnixStream { fd: 3, local: (unnamed), peer: "/tmp/ssh-XXXXbdaq4N/agent.81672" (pathname) }
    -- found 2 keys in ssh-agent --
    ssh-rsa SHA256:DTt4MACbRj4K7TFBvfr0wP0QqZt+i5/8k40Ky/aBo38= id_rsa
    ssh-rsa SHA256:q2f9rM7M7PzVV4o67x73zkW2HuH82lgATRzeuQt160Y= joyent_key

    curl -sS --header 'date: Sat, 04 Aug 2018 17:07:50 GMT' --header 'authorization: Signature keyId="/bahamas10/keys/e4:e3:97:89:62:eb:35:91:90:f9:5a:97:bb:35:50:72",algorithm="rsa-sha1",headers="date",signature="..."' 'https://us-east.manta.joyent.com/bahamas10/stor/foo/dir';echo

    hi

What Works
----------

1. List `ssh-agent` keys
2. Sign data with `ssh-agent`
3. Generate `Authorization` header using an http signature with `ssh-agent`
4. Constructing a `curl` command to get data from manta
5. Parsing newline JSON (though, it's all loaded in memory first)

What Needs to be done
---------------------

1. Find a good HTTP client library that works on SmartOS (and not fork `curl`)
2. Abstract a bunch of this logic and clean it up
3. Support more than just `ssh-agent`
