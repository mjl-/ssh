implement Authproto;

# SSH DSA authentication.  Based on SSH RSA authentication code.
#
# Client protocol:
#	read public key
#		if you don't like it, read another, repeat
#	write challenge
#	read response
# all numbers are hexadecimal biginits parsable with strtomp.
#

include "sys.m";
	sys: Sys;
	sprint: import sys;

include "draw.m";

include "keyring.m";
	kr: Keyring;
	IPint, DSAsk, DSApk: import kr;

include "../appl/cmd/auth/factotum/authio.m";
	authio: Authio;
	Aattr, Aval, Aquery: import Authio;
	Attr, IO, Key, Authinfo: import authio;
	eqbytes, memrandom: import authio;
	lookattrval: import authio;


init(f: Authio): string
{
	authio = f;
	sys = load Sys Sys->PATH;
	kr = load Keyring Keyring->PATH;
	return nil;
}

interaction(attrs: list of ref Attr, io: ref IO): string
{
	role := lookattrval(attrs, "role");
	if(role == nil)
		return "role not specified";
	if(role != "client")
		return "only client role supported";
	sk: ref DSAsk;
	keys: list of ref Key;
	err: string;
	for(;;){
		waitread(io);
		(keys, err) = io.findkeys(attrs, "");
		if(keys != nil)
			break;
		io.error(err);
	}
	for(; keys != nil; keys = tl keys){
		(sk, err) = keytodsa(hd keys);
		if(sk != nil){
			r := sys->aprint("%s %s %s %s", sk.pk.p.iptostr(16), sk.pk.q.iptostr(16), sk.pk.alpha.iptostr(16), sk.pk.key.iptostr(16));
			while(!io.reply2read(r, len r))
				waitread(io);
			data := io.rdwr();
			if(data != nil){
				chal := IPint.strtoip(string data, 16);
				if(chal == nil){
					io.error("invalid challenge value");
					continue;
				}
				sig := sk.sign(chal);
				# xxx handle sig == nil?
				b := sys->aprint("%s %s", sig.r.iptostr(16), sig.s.iptostr(16));
				io.write(b, len b);
				io.done(nil);
				return nil;
			}
		}
	}
	for(;;){
		io.error("no key matches "+authio->attrtext(attrs));
		waitread(io);
	}
}

waitread(io: ref IO)
{
	while(io.rdwr() != nil)
		io.error("no current key");
}

Badkey: exception(string);

ipint(attrs: list of ref Attr, name: string): ref IPint raises Badkey
{
	s := lookattrval(attrs, name);
	if(s == nil)
		raise Badkey("missing attribute "+name);
	m := IPint.strtoip(s, 16);
	if(m == nil)
		raise Badkey("invalid value for "+name);
	return m;
}

keytodsa(k: ref Key): (ref DSAsk, string)
{
	sk := ref DSAsk;
	sk.pk = ref DSApk;
	{
		sk.pk.p = ipint(k.attrs, "p");
		sk.pk.q = ipint(k.attrs, "q");
		sk.pk.alpha = ipint(k.attrs, "alpha");
		sk.pk.key = ipint(k.attrs, "key");
		sk.secret = ipint(k.secrets, "!secret");
	}exception e{
	Badkey =>
		return (nil, "dsa key "+e);
	}
	return (sk, nil);
}

keycheck(k: ref Authio->Key): string
{
	return keytodsa(k).t1;
}

say(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}
