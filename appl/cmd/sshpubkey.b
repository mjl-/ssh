implement Sshpubkey;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "attrdb.m";
	attrdb: Attrdb;
	Tuples, Attr: import attrdb;
include "string.m";
	str: String;
include "encoding.m";
	base64: Encoding;
include "keyring.m";
	keyring: Keyring;
	IPint: import keyring;
include "util0.m";
	util: Util0;
	fail: import util;
include "../lib/sshfmt.m";
	sshfmt: Sshfmt;
	valstr, valmpint: import sshfmt;

Sshpubkey: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	attrdb = load Attrdb Attrdb->PATH;
	str = load String String->PATH;
	base64 = load Encoding Encoding->BASE64PATH;
	keyring = load Keyring Keyring->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sshfmt = load Sshfmt Sshfmt->PATH;
	sshfmt->init();

	user := "none@localhost";
	arg->init(args);
	arg->setusage(arg->progname()+ "[-u user]");
	while((c := arg->opt()) != 0)
		case c {
		'u' =>	user = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 0)
		arg->usage();

	b := bufio->fopen(sys->fildes(0), Bufio->OREAD);
	if(b == nil)
		fail(sprint("bufio fopen: %r"));
	nr := 0;
	for(;;) {
		l := b.gets('\n');
		if(l == nil)
			break;
		if(str->prefix("key ", l))
			l = l[len "key ":];
		(tups, err) := attrdb->parseline(l, ++nr);
		if(err != nil)
			fail(err);
		if(tups == nil)
			continue;

		proto := get(nr, tups, "proto");
		case proto {
		"ssh-rsa" =>
			n := get(nr, tups, "n");
			ek := get(nr, tups, "ek");
			vals := array[] of {
				valstr("ssh-rsa"),
				valmpint(IPint.strtoip(ek, 16)),
				valmpint(IPint.strtoip(n, 16)),
			};
			keystr := base64->enc(sshfmt->pack(vals, 0));
			sys->print("ssh-rsa %s %q\n", keystr, user);
		"ssh-dsa" =>
			p := get(nr, tups, "p");
			q := get(nr, tups, "q");
			alpha := get(nr, tups, "alpha");
			key := get(nr, tups, "key");
			vals := array[] of {
				valstr("ssh-dss"),
				valmpint(IPint.strtoip(p, 16)),
				valmpint(IPint.strtoip(q, 16)),
				valmpint(IPint.strtoip(alpha, 16)),
				valmpint(IPint.strtoip(key, 16)),
			};
			keystr := base64->enc(sshfmt->pack(vals, 0));
			sys->print("ssh-dss %s %q\n", keystr, user);
		}
	}
}

get(nr: int, tups: ref Tuples, name: string): string
{
	l := tups.find(name);
	if(len l == 0)
		fail(sprint("line %d, missing attribute %#q", nr, name));
	if(len l > 1)
		fail(sprint("line %d, multiple values for attribute %#q", nr, name));
	return (hd l).val;
}
