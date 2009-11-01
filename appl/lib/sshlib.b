implement Sshlib;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "env.m";
	env: Env;
include "string.m";
	str: String;
include "security.m";
	random: Random;
include "keyring.m";
	kr: Keyring;
	IPint, RSAsk, RSApk, RSAsig, DSAsk, DSApk, DSAsig, DigestState: import kr;
include "factotum.m";
	fact: Factotum;
include "encoding.m";
	base16, base64: Encoding;
include "util0.m";
	util: Util0;
	readfile, hex, prefix, suffix, rev, l2a, max, min, warn, join, eq, g32i, g64, p32, p32i, p64: import util;
include "sshfmt.m";
	sshfmt: Sshfmt;
	Val: import sshfmt;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshfmt;
	valbool, valbyte, valint, valbig, valmpint, valnames, valstr, valbytes, valbuf: import sshfmt;
include "sshlib.m";


Padmin:	con 4;
Packetunitmin:	con 8;
Pktlenmin:	con 16;
Pktlenmax:	con 35000;  # from ssh rfc

Dhexchangemin:	con 1*1024;
Dhexchangewant:	con 1*1024;  # 2*1024 is recommended, but it is too slow
Dhexchangemax:	con 8*1024;

Seqmax:	con big 2**32;

dhgroup1, dhgroup14: ref Dh;

# what we support.  these arrays are index by types in sshlib.m, keep them in sync!
knownkex := array[] of {
	"diffie-hellman-group1-sha1",
	"diffie-hellman-group14-sha1",
	"diffie-hellman-group-exchange-sha1",
};
knownhostkey := array[] of {
	"ssh-dss",
	"ssh-rsa",
};
knownenc := array[] of {
	"none",
	"aes128-cbc",
	"aes192-cbc",
	"aes256-cbc",
	"idea-cbc",  # untested
	"arcfour",
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
	"arcfour128",
	"arcfour256",
	"3des-cbc",
	# "blowfish-cbc",  # doesn't work
};
knownmac := array[] of {
	"none",
	"hmac-sha1",
	"hmac-sha1-96",
	"hmac-md5",
	"hmac-md5-96",
};
knowncompr := array[] of {
	"none",
};
knownauthmeth := array[] of {
	"publickey",
	"password",
};

# what we want to do by default, first is preferred
defkex :=	array[] of {Dgroupexchange, Dgroup14, Dgroup1};
defhostkey :=	array[] of {Hrsa, Hdss};
defenc :=	array[] of {Eaes128cbc, Eaes192cbc, Eaes256cbc, Eaes128ctr, Eaes192ctr, Eaes256ctr, Earcfour128, Earcfour256, Earcfour, E3descbc};
defmac :=	array[] of {Msha1_96, Msha1, Mmd5, Mmd5_96};
defcompr :=	array[] of {Cnone};
defauthmeth :=	array[] of {Apublickey, Apassword};

msgnames := array[] of {
SSH_MSG_DISCONNECT		=> "disconnect",
SSH_MSG_IGNORE			=> "ignore",
SSH_MSG_UNIMPLEMENTED		=> "unimplemented",
SSH_MSG_DEBUG			=> "debug",
SSH_MSG_SERVICE_REQUEST		=> "service request",
SSH_MSG_SERVICE_ACCEPT		=> "service accept",
SSH_MSG_KEXINIT			=> "kex init",
SSH_MSG_NEWKEYS			=> "new keys",

SSH_MSG_KEXDH_INIT		=> "kexdh init",
SSH_MSG_KEXDH_REPLY		=> "kexdh reply",
SSH_MSG_KEXDH_GEX_INIT		=> "kexdh gex init",
SSH_MSG_KEXDH_GEX_REPLY		=> "kexdh gex reply",
SSH_MSG_KEXDH_GEX_REQUEST	=> "kexdh gex request",

SSH_MSG_USERAUTH_REQUEST	=> "userauth request",
SSH_MSG_USERAUTH_FAILURE	=> "userauth failure",
SSH_MSG_USERAUTH_SUCCESS	=> "userauth success",
SSH_MSG_USERAUTH_BANNER		=> "userauth banner",

SSH_MSG_GLOBAL_REQUEST		=> "global request",
SSH_MSG_REQUEST_SUCCESS		=> "request success",
SSH_MSG_REQUEST_FAILURE		=> "request failure",
SSH_MSG_CHANNEL_OPEN		=> "channel open",
SSH_MSG_CHANNEL_OPEN_CONFIRMATION	=> "channel open confirmation",
SSH_MSG_CHANNEL_OPEN_FAILURE	=> "open failure",
SSH_MSG_CHANNEL_WINDOW_ADJUST	=> "window adjust",
SSH_MSG_CHANNEL_DATA		=> "channel data",
SSH_MSG_CHANNEL_EXTENDED_DATA	=> "channel extended data",
SSH_MSG_CHANNEL_EOF		=> "channel eof",
SSH_MSG_CHANNEL_CLOSE		=> "channel close",
SSH_MSG_CHANNEL_REQUEST		=> "channel request",
SSH_MSG_CHANNEL_SUCCESS		=> "channel success",
SSH_MSG_CHANNEL_FAILURE		=> "channel failure",
};

init()
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	bufio->open("/dev/null", Bufio->OREAD);
	env = load Env Env->PATH;
	str = load String String->PATH;
	random = load Random Random->PATH;
	kr = load Keyring Keyring->PATH;
	base16 = load Encoding Encoding->BASE16PATH;
	base64 = load Encoding Encoding->BASE64PATH;
	fact = load Factotum Factotum->PATH;
	fact->init();
	util = load Util0 Util0->PATH;
	util->init();
	sshfmt = load Sshfmt Sshfmt->PATH;
	sshfmt->init();

	group1primestr := 
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF";
	group1prime := IPint.strtoip(group1primestr, 16);
	group1gen := IPint.inttoip(2);
	dhgroup1 = ref Dh (group1prime, group1gen, 1024);

	group14primestr :=
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF";
	group14prime := IPint.strtoip(group14primestr, 16);
	group14gen := IPint.inttoip(2);
	dhgroup14 = ref Dh (group14prime, group14gen, 2048);
}

msgname(t: int): string
{
	if(t < 0 || t >= len msgnames || msgnames[t] == nil)
		return "unknown";
	return msgnames[t];
}


handshake(fd: ref Sys->FD, addr: string, wantcfg: ref Cfg): (ref Sshc, string)
{
	b := bufio->fopen(fd, Bufio->OREAD);
	if(b == nil)
		return (nil, sprint("bufio fopen: %r"));

	lident := "SSH-2.0-inferno0";
	if(sys->fprint(fd, "%s\r\n", lident) < 0)
		return (nil, sprint("write handshake: %r"));

	rident: string;
	for(;;) {
		rident = b.gets('\n');
		if(rident == nil || rident[len rident-1] != '\n')
			return (nil, sprint("eof before identification line"));
		if(!prefix("SSH-", rident))
			continue;
		if(len rident > 255)
			return (nil, sprint("identification from remote too long, invalid"));

		rident = rident[:len rident-1];
		if(suffix("\r", rident))
			rident = rident[:len rident-1];

		# note: rident (minus \n or \r\n) is used in key exchange, must be left as is
		(rversion, rname) := str->splitstrl(rident[len "SSH-":], "-");
		if(rname == nil)
			return (nil, sprint("bad remote identification %#q, missing 'name'", rident));
		rcomment: string;
		(rname, rcomment) = str->splitstrl(rname[1:], " ");
		say(sprint("have remote version %q, name %q, comment %q", rversion, rname, rcomment));

		if(rversion != "2.0" && rversion != "1.99")
			return (nil, sprint("unsupported remote version %#q", rversion));
		break;
	}

	nilkey := ref Keys (Cryptalg.new(Enone), Macalg.new(Enone));
	c := ref Sshc (
		fd, b, addr, nil,
		big 0, big 0, big 0, big 0,
		nilkey, nilkey, nil, nil,
		lident, rident,
		wantcfg, nil,
		nil,
		nil,
		0, nil, nil, nil
	);
	return (c, nil);
}

keyexchangestart(c: ref Sshc): ref Tssh
{
	say("keyexchangestart");
	nilnames := valnames(nil);
	cookie := random->randombuf(Random->NotQuiteRandom, 16);
	vals := array[] of {
		valbuf(cookie),
		valnames(c.wantcfg.kex),
		valnames(c.wantcfg.hostkey),
		valnames(c.wantcfg.encout), valnames(c.wantcfg.encin),
		valnames(c.wantcfg.macout), valnames(c.wantcfg.macin),
		valnames(c.wantcfg.comprout), valnames(c.wantcfg.comprin),
		nilnames, nilnames,
		valbool(0),
		valint(0),
	};

	tm := ref Tssh(big 0, SSH_MSG_KEXINIT, vals, 0, nil);
	c.kexstate |= Kexinitsent;

	nvals := array[1+len vals] of ref Val;
	nvals[0] = valbyte(byte SSH_MSG_KEXINIT);
	nvals[1:] = vals;
	c.clkexinit = sshfmt->pack(nvals, 0);

	return tm;
}

keyexchange(c: ref Sshc, m: ref Rssh): (int, int, list of ref Tssh, string)
{
	{
		(notimpl, kexdone, tms) := xkeyexchange(c, m);
		return (notimpl, kexdone, tms, nil);
	} exception x {
	"kex:*" =>
		return (0, 0, nil, x[len "kex:":]);
	"parse:*" =>
		return (0, 0, nil, x[len "parse:":]);
	}
}

xparseall(m: ref Rssh, l: list of int): array of ref Val
{
	(v, err) := sshfmt->parseall(m.buf[1:], l);
	if(err != nil)
		raise "parse:"+err;
	return v;
}

kexerror(s: string)
{
	raise "kex:"+s;
}

xkeyexchange(c: ref Sshc, m: ref Rssh): (int, int, list of ref Tssh)
{
	case m.t {
	SSH_MSG_KEXINIT =>
		kexmsg := list of {16, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tbool, Tint};
		v := xparseall(m, kexmsg);

		c.srvkexinit = m.buf;
		o := 1;
		remcfg := ref Cfg (
			nil,
			v[o++].getnames(),
			v[o++].getnames(),
			v[o++].getnames(), v[o++].getnames(),
			v[o++].getnames(), v[o++].getnames(),
			v[o++].getnames(), v[o++].getnames(),
			nil
		);
		if(dflag) {
			say("languages client to server: "+v[o++].text());
			say("languages server to client: "+v[o++].text());
			say("first kex packet follows: "+v[o++].text());
			say("out config:");
			say(c.wantcfg.text());
			say("from remote:");
			say(remcfg.text());
		}
		err: string;
		(c.usecfg, err) = Cfg.match(c.wantcfg, remcfg);
		if(err != nil)
			kexerror(err);
		if(dflag) say("chosen config:\n"+c.usecfg.text());

		c.auths = authmethods(c.usecfg.authmeth);
		(c.newtosrv, c.newfromsrv) = Keys.new(c.usecfg);
		case hd c.usecfg.kex {
		"diffie-hellman-group1-sha1" =>
			c.kex = ref Kex (0, dhgroup1, nil, nil);
		"diffie-hellman-group14-sha1" =>
			c.kex = ref Kex (0, dhgroup14, nil, nil);
		"diffie-hellman-group-exchange-sha1" =>
			c.kex = ref Kex (1, nil, nil, nil);
		* =>
			raise "internal error, unknown kex alg";
		}

		tms: list of ref Tssh;
		c.kexstate |= Kexinitreceived;
		if((c.kexstate & Kexinitsent) == 0)
			tms = keyexchangestart(c)::nil;

		tm: ref Tssh;
		if(c.kex.new) {
			vals := array[] of {valint(Dhexchangemin), valint(Dhexchangewant), valint(Dhexchangemax)};
			tm = ref Tssh (big 0, SSH_MSG_KEX_DH_GEX_REQUEST, vals, 0, nil);
		} else {
			gendh(c.kex);
			vals := array[] of {valmpint(c.kex.e)};
			tm = ref Tssh (big 0, SSH_MSG_KEXDH_INIT, vals, 0, nil);
		}
		tms = tm::tms;
		return (0, 0, rev(tms));

	SSH_MSG_NEWKEYS =>
		xparseall(m, nil);
		say("server wants to use newkeys");

		if((c.kexstate & Havenewkeys) == 0)
			kexerror("server wants to use new keys, but none are pending");

		tms: list of ref Tssh;
		if((c.kexstate & Newkeyssent) == 0) {
			say("writing newkeys to remote");
			tm := ref Tssh (big 0, SSH_MSG_NEWKEYS, nil, 0, nil);
			# pack now we still have the old keys
			tm.packed = packpacket(c, tm);
			tms = tm::nil;
			c.kexstate |= Newkeyssent;
		}

		say("now using new keys");
		c.tosrv = c.newtosrv;
		c.fromsrv = c.newfromsrv;
		c.newtosrv = c.newfromsrv = nil;
		c.nkeypkts = c.nkeybytes = big 0;
		c.kexstate &= ~(Kexinitsent|Kexinitreceived|Newkeyssent|Newkeysreceived|Havenewkeys);
		return (0, 1, tms);

	SSH_MSG_KEXDH_INIT =>
		kexerror("received SSH_MSG_KEXDH_INIT from server, invalid");

	SSH_MSG_KEXDH_REPLY or
	SSH_MSG_KEXDH_GEX_INIT to # xxx is gex init valid?
	SSH_MSG_KEXDH_GEX_REQUEST =>

		if((c.kexstate & (Kexinitsent|Kexinitreceived)) != (Kexinitsent|Kexinitreceived))
			kexerror("kexdh messages but no kexinit in progress!");
		if((c.kexstate & Havenewkeys) != 0)
			kexerror("kexhd message, but already Havenewkeys?");

		if(c.kex.new && m.t == SSH_MSG_KEX_DH_GEX_REPLY || !c.kex.new && m.t == SSH_MSG_KEXDH_REPLY) {
			v := xparseall(m, list of {Tstr, Tmpint, Tstr});

			#string    server public host key and certificates (K_S)
			#mpint     f
			#string    signature of H
			srvksval := v[0];
			srvfval := v[1];
			srvsigh := v[2].getbytes();
			srvks := srvksval.getbytes();
			srvf := srvfval.getipint();

			# C then
			# computes K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S
			# || e || f || K), and verifies the signature s on H.
			say("calculating key from f from remote");
			key := srvf.expmod(c.kex.x, c.kex.dhgroup.prime);
			c.kex.x = nil;
			#say(sprint("key %s", key.iptostr(16)));
			hashbufs: list of array of byte;
			if(c.kex.new)
				hashbufs = list of {
					valstr(c.lident).pack(),
					valstr(c.rident).pack(),
					valbytes(c.clkexinit).pack(),
					valbytes(c.srvkexinit).pack(),
					srvksval.pack(),
					valint(Dhexchangemin).pack(),
					valint(Dhexchangewant).pack(),
					valint(Dhexchangemax).pack(),
					valmpint(c.kex.dhgroup.prime).pack(),
					valmpint(c.kex.dhgroup.gen).pack(),
					valmpint(c.kex.e).pack(),
					srvfval.pack(),
					valmpint(key).pack()
				};
			else
				hashbufs = list of {
					valstr(c.lident).pack(),
					valstr(c.rident).pack(),
					valbytes(c.clkexinit).pack(),
					valbytes(c.srvkexinit).pack(),
					srvksval.pack(),
					valmpint(c.kex.e).pack(),
					srvfval.pack(),
					valmpint(key).pack()
				};
			dhhash := sha1many(hashbufs);
			zero(c.clkexinit);
			c.clkexinit = nil;
			zero(c.srvkexinit);
			c.srvkexinit = nil;
			srvfval = nil;
			if(dflag) say(sprint("hash on dh %s", fingerprint(dhhash)));

			if(c.sessionid == nil)
				c.sessionid = dhhash;

			err := verifyhostkey(c, hd c.usecfg.hostkey, srvks, srvsigh, dhhash);
			if(err != nil)
				kexerror(err);

			# calculate session keys
			#Encryption keys MUST be computed as HASH, of a known value and K, as follows:
			#o  Initial IV client to server: HASH(K || H || "A" || session_id)
			#    (Here K is encoded as mpint and "A" as byte and session_id as raw
			#   data.  "A" means the single character A, ASCII 65).
			#o  Initial IV server to client: HASH(K || H || "B" || session_id)
			#o  Encryption key client to server: HASH(K || H || "C" || session_id)
			#o  Encryption key server to client: HASH(K || H || "D" || session_id)
			#o  Integrity key client to server: HASH(K || H || "E" || session_id)
			#o  Integrity key server to client: HASH(K || H || "F" || session_id)

			keypack := valmpint(key).pack();

			keybitsout := c.newtosrv.crypt.keybits;
			keybitsin := c.newfromsrv.crypt.keybits;
			macbitsout := c.newtosrv.mac.keybytes*8;
			macbitsin := c.newfromsrv.mac.keybytes*8;

			ivc2s := genkey(keybitsout, keypack, dhhash, "A", c.sessionid);
			ivs2c := genkey(keybitsin, keypack, dhhash, "B", c.sessionid);
			enckeyc2s := genkey(keybitsout, keypack, dhhash, "C", c.sessionid);
			enckeys2c := genkey(keybitsin, keypack, dhhash, "D", c.sessionid);
			mackeyc2s := genkey(macbitsout, keypack, dhhash, "E", c.sessionid);
			mackeys2c := genkey(macbitsin, keypack, dhhash, "F", c.sessionid);

			c.newtosrv.crypt.setup(enckeyc2s, ivc2s);
			c.newfromsrv.crypt.setup(enckeys2c, ivs2c);
			c.newtosrv.mac.setup(mackeyc2s);
			c.newfromsrv.mac.setup(mackeys2c);

			say("we want to use newkeys");
			c.kexstate |= Havenewkeys|Newkeyssent;
			tm := ref Tssh (big 0, SSH_MSG_NEWKEYS, nil, 0, nil);
			return (0, 0, tm::nil);

		} else if(c.kex.new && m.t == SSH_MSG_KEX_DH_GEX_GROUP) {
			v := xparseall(m, list of {Tmpint, Tmpint});
			prime := v[0].getipint();
			gen := v[1].getipint();
			# xxx should verify these values are sane.
			c.kex.dhgroup = ref Dh (prime, gen, prime.bits());

			gendh(c.kex);

			vals := array[] of {valmpint(c.kex.e)};
			tm := ref Tssh (big 0, SSH_MSG_KEX_DH_GEX_INIT, vals, 0, nil);
			return (0, 0, tm::nil);
		} else {
			kexerror(sprint("unexpected kex message, t %d, new %d", m.t, c.kex.new));
		}
	}
	return (1, 0, nil);
}

genkey(needbits: int, k, h: array of byte, x: string, sessionid: array of byte): array of byte
{
	nbytes := needbits/8;
	if(dflag) say(sprint("genkey, needbits %d, nbytes %d", needbits, nbytes));
	k1 := sha1many(list of {k, h, array of byte x, sessionid});
	if(nbytes <= len k1)
		return k1[:nbytes];
	ks := list of {k1};
	key := k1;
	while(len key < nbytes) {
		kx := sha1many(k::h::ks);
		nkey := array[len key+len kx] of byte;
		nkey[:] = key;
		nkey[len key:] = kx;
		key = nkey;
		ks = rev(kx::rev(ks));
	}
	return key[:nbytes];
}

gendh(k: ref Kex)
{
	# 1. C generates a random number x (1 < x < q) and computes
	# e = g^x mod p.  C sends e to S.
	if(dflag) say(sprint("gendh, nbits %d", k.dhgroup.nbits));

	k.x = IPint.random(k.dhgroup.nbits, k.dhgroup.nbits); # xxx sane params?
	k.e = k.dhgroup.gen.expmod(k.x, k.dhgroup.prime);

	if(dflag) say(sprint("k.x %s", k.x.iptostr(16)));
	if(dflag) say(sprint("k.e %s", k.e.iptostr(16)));
}


userauth(c: ref Sshc, m: ref Rssh): (int, int, ref Tssh, string)
{
	{
		return xuserauth(c, m);
	} exception x {
	"parse:*" =>
		return (0, 0, nil, x[len "parse:":]);
	}
}

xuserauth(c: ref Sshc, m: ref Rssh): (int, int, ref Tssh, string)
{
	case m.t {
	SSH_MSG_USERAUTH_FAILURE =>
		v := xparseall(m, list of {Tnames, Tbool});
		authmeths := v[0].getnames();
		partialok := v[1].getbool();

		warn("authentication failed");
		say(sprint("other auth methods that can be tried: %s", join(authmeths, ",")));
		say(sprint("partical succes %d", partialok));

		(tm, err) := userauthnext(c);
		if(err != nil)
			return (0, 0, tm, err);
		return (0, 0, tm, nil);

	SSH_MSG_USERAUTH_SUCCESS =>
		xparseall(m, nil);
		say("logged in!");
		return (0, 1, nil, nil);
	}
	return (1, 0, nil, nil);
}

userauthnext(c: ref Sshc): (ref Tssh, string)
{
	while(c.auths != nil) {
		meth := hd c.auths;
		c.auths = tl c.auths;

		tm: ref Tssh;
		err: string;
		case meth {
		"rsa" =>	(tm, err) = authrsa(c);
		"dsa" =>	(tm, err) = authdsa(c);
		"password" =>	(tm, err) = authpassword(c);
		* =>
			raise "internal error, unknown authentication method";
		}
		if(tm != nil)
			return (tm, nil);
		if(err != nil)
			say(err);
	}
	return (nil, "no more authentication methods");
}


sha1der := array[] of {
byte 16r30, byte 16r21,
byte 16r30, byte 16r09,
byte 16r06, byte 16r05,
byte 16r2b, byte 16r0e, byte 16r03, byte 16r02, byte 16r1a,
byte 16r05, byte 16r00,
byte 16r04, byte 16r14,
};
rsasha1msg(d: array of byte, msglen: int): array of byte
{
	h := sha1(d);
	msg := array[msglen] of {* => byte 16rff};
	msg[0] = byte 0;
	msg[1] = byte 1;
	msg[len msg-(1+len sha1der+len h)] = byte 0;
	msg[len msg-(len sha1der+len h):] = sha1der;
	msg[len msg-len h:] = h;
	return msg;
}

authrsa(c: ref Sshc): (ref Tssh, string)
{
	say("doing rsa public-key authentication");

	fd := sys->open("/mnt/factotum/rpc", Sys->ORDWR);
	if(fd == nil)
		return (nil, sprint("open factotum: %r"));

	user := c.user;
	if(user == nil)
		user = string readfile("/dev/user", 128);
	(v, a) := fact->rpc(fd, "start", sys->aprint("proto=ssh-rsa role=client user=%q addr=%q %s", user, c.addr, c.wantcfg.keyspec));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);  # xxx should probably try all keys available.  needs some code.
	if(v != "ok")
		return (nil, sprint("factotum: %s: %s", v, string a));
	(rsaepubs, rsans) := str->splitstrl(string a, " ");
	if(rsans == nil)
		return (nil, "bad response for rsa keys from factotum");
	rsans = rsans[1:];
	rsaepub := IPint.strtoip(rsaepubs, 16);
	rsan := IPint.strtoip(rsans, 16);

	# our public key
	pkvals := array[] of {
		valstr("ssh-rsa"),
		valmpint(rsaepub),
		valmpint(rsan),
	};
	pkblob := sshfmt->pack(pkvals, 0);

	# data to sign
	sigdatvals := array[] of {
		valbytes(c.sessionid),
		valbyte(byte SSH_MSG_USERAUTH_REQUEST),
		valstr(user),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-rsa"),
		valbytes(pkblob),
	};
	sigdatblob := sshfmt->pack(sigdatvals, 0);

	# sign it
	sigmsg := rsasha1msg(sigdatblob, rsan.bits()/8);

	(v, a) = fact->rpc(fd, "write", array of byte base16->enc(sigmsg));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);
	if(v != "ok")
		return (nil, sprint("factotum: %s: %s", v, string a));
	sigbuf := base16->dec(string a);

	sigvals := array[] of {valstr("ssh-rsa"), valbytes(sigbuf)};
	sig := sshfmt->pack(sigvals, 0);

	authvals := array[] of {
		valstr(user),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-rsa"),
		valbytes(pkblob),
		valbytes(sig),
	};
	tm := ref Tssh (big 0, SSH_MSG_USERAUTH_REQUEST, authvals, 0, nil);
	return (tm, nil);
}

authdsa(c: ref Sshc): (ref Tssh, string)
{
	say("doing dsa public-key authentication");

	fd := sys->open("/mnt/factotum/rpc", Sys->ORDWR);
	if(fd == nil)
		return (nil, sprint("open factotum: %r"));

	user := c.user;
	if(user == nil)
		user = string readfile("/dev/user", 128);
	(v, a) := fact->rpc(fd, "start", sys->aprint("proto=ssh-dsa role=client user=%q addr=%q %s", user, c.addr, c.wantcfg.keyspec));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);  # xxx should probably try all keys available.  needs some code.
	if(v != "ok")
		return (nil, sprint("factotum: %s: %s", v, string a));
	pkl := sys->tokenize(string a, " ").t1;
	if(len pkl != 4)
		return (nil, "bad response for dsa public key from factotum");
	pk := l2a(pkl);
	p := IPint.strtoip(pk[0], 16);
	q := IPint.strtoip(pk[1], 16);
	alpha := IPint.strtoip(pk[2], 16);
	key := IPint.strtoip(pk[3], 16);

	# our public key
	pkvals := array[] of {
		valstr("ssh-dss"),
		valmpint(p),
		valmpint(q),
		valmpint(alpha),
		valmpint(key),
	};
	pkblob := sshfmt->pack(pkvals, 0);

	# data to sign
	sigdatvals := array[] of {
		valbytes(c.sessionid),
		valbyte(byte SSH_MSG_USERAUTH_REQUEST),
		valstr(user),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-dss"),
		valbytes(pkblob),
	};
	sigdatblob := sshfmt->pack(sigdatvals, 0);

	# sign it
	(v, a) = fact->rpc(fd, "write", array of byte base16->enc(sha1(sigdatblob)));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);
	if(v != "ok")
		return (nil, sprint("factotum: %s: %s", v, string a));
	sigtoks := sys->tokenize(string a, " ").t1;
	sigbuf := array[20+20] of {* => byte 0};
	rbuf := base16->dec(hd sigtoks);
	sbuf := base16->dec(hd tl sigtoks);
	sigbuf[20-len rbuf:] = rbuf;
	sigbuf[40-len sbuf:] = sbuf;

	# the signature to put in the auth request packet
	sigvals := array[] of {valstr("ssh-dss"), valbytes(sigbuf)};
	sig := sshfmt->pack(sigvals, 0);

	authvals := array[] of {
		valstr(user),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-dss"),
		valbytes(pkblob),
		valbytes(sig),
	};
	tm := ref Tssh (big 0, SSH_MSG_USERAUTH_REQUEST, authvals, 0, nil);
	return (tm, nil);
}

authpassword(c: ref Sshc): (ref Tssh, string)
{
	say("doing password authentication");
	spec := sprint("proto=pass role=client service=ssh addr=%q", c.addr);
	if(c.user != nil)
		spec += sprint(" user=%q", c.user);
	if(c.wantcfg.keyspec != nil)
		spec += " "+c.wantcfg.keyspec;
	(user, pass) := fact->getuserpasswd(spec);
	if(user == nil)
		return (nil, sprint("no username"));
	c.user = user;
	vals := array[] of {
		valstr(user),
		valstr("ssh-connection"),
		valstr("password"),
		valbool(0),
		valstr(pass),
	};
	tm := ref Tssh (big 0, SSH_MSG_USERAUTH_REQUEST, vals, 100, nil);
	return (tm, nil);
}


verifyhostkey(c: ref Sshc, name: string, ks, sig, h: array of byte): string
{
	case name {
	"ssh-rsa" =>	return verifyrsa(c, ks, sig, h);
	"ssh-dss" =>	return verifydsa(c, ks, sig, h);
	}
	raise "missing case";
}

verifyhostkeyfile(c: ref Sshc, alg, fp, hostkey: string): string
{
	fd := sys->open("/chan/sshkeys", Sys->OWRITE);
	if(fd != nil) {
		if(sys->fprint(fd, "%q %q %q %q", c.addr, alg, fp, hostkey) < 0)
			return sprint("%r");
		return nil;
	}

	# no sshkeys running, read $home/lib/sshkeys for exact matches
	f := sprint("%s/lib/sshkeys", env->getenv("home"));
	b := bufio->open(f, sys->OREAD);
	if(b == nil)
		return sprint("open %q: %r", f);
	line := 0;
	for(;;) {
		s := b.gets('\n');
		if(s == nil)
			break;
		line++;
		if(s[len s-1] != '\n')
			s = s[:len s-1];
		t := l2a(str->unquoted(s));
		if(len t != 4)
			return sprint("%s:%d: malformed line", f, line);
		if(t[0] == c.addr && t[1] == alg && t[2] == fp && t[3] == hostkey)
			return nil;
	}
	return "host key denied";
}

verifyrsa(c: ref Sshc, ks, sig, h: array of byte): string
{
	# ssh-rsa host key:
	#string    "ssh-rsa"
	#mpint     e
	#mpint     n

	(keya, err) := sshfmt->parseall(ks, list of {Tstr, Tmpint, Tmpint});
	if(err != nil)
		return "bad ssh-rsa host key: "+err;
	signame := keya[0].getstr();
	if(signame != "ssh-rsa")
		return sprint("host key %#q, expected 'ssh-rsa'", signame);
	srvrsae := keya[1];
	srvrsan := keya[2];
	rsan := srvrsan.getipint();
	rsae := srvrsae.getipint();
	if(dflag) say(sprint("server rsa key, e %s, n %s", srvrsae.text(), srvrsan.text()));

	fp := fingerprint(md5(ks));
	hostkey := base64->enc(ks);
	if(dflag) say("rsa fingerprint: "+fp);

	err = verifyhostkeyfile(c, "ssh-rsa", fp, hostkey);
	if(err != nil)
		return err;

	# signature
	# string    "ssh-rsa"
	# string    rsa_signature_blob
	siga := keya;
	(siga, err) = sshfmt->parseall(sig, list of {Tstr, Tstr});
	if(err != nil)
		return "bad ssh-rsa signature: "+err;
	signame = siga[0].getstr();
	if(signame != "ssh-rsa")
		return sprint("signature is %#q, expected 'ssh-rsa'", signame);
	sigblob := siga[1].getbytes();

	rsapk := ref RSApk (rsan, rsae);
	sigmsg := rsasha1msg(h, rsan.bits()/8);
	rsasig := ref RSAsig (IPint.bebytestoip(sigblob));
	ok := rsapk.verify(rsasig, IPint.bebytestoip(sigmsg));
	if(!ok)
		return "rsa signature does not match";
	return nil;
}

verifydsa(c: ref Sshc, ks, sig, h: array of byte): string
{
	# string    "ssh-dss"
	# mpint     p
	# mpint     q
	# mpint     g
	# mpint     y

	(keya, err) := sshfmt->parseall(ks, list of {Tstr, Tmpint, Tmpint, Tmpint, Tmpint});
	if(err != nil)
		return "bad ssh-dss host key: "+err;
	signame := keya[0].getstr();
	if(signame != "ssh-dss")
		return sprint("host key is %#q, expected 'ssh-dss'", signame);
	srvdsap := keya[1];
	srvdsaq := keya[2];
	srvdsag := keya[3];
	srvdsay := keya[4];
	if(dflag) say(sprint("server dsa key, p %s, q %s, g %s, y %s", srvdsap.text(), srvdsaq.text(), srvdsag.text(), srvdsay.text()));

	fp := fingerprint(md5(ks));
	hostkey := base64->enc(ks);

	err = verifyhostkeyfile(c, "ssh-dss", fp, hostkey);
	if(err != nil)
		return err;

	# string    "ssh-dss"
	# string    dss_signature_blob

	#   The value for 'dss_signature_blob' is encoded as a string containing
	#   r, followed by s (which are 160-bit integers, without lengths or
	#   padding, unsigned, and in network byte order).
	siga := keya;
	(siga, err) = sshfmt->parseall(sig, list of {Tstr, Tstr});
	if(err != nil)
		return "bad ssh-dss signature: "+err;
	signame = siga[0].getstr();
	if(signame != "ssh-dss")
		return sprint("signature is %#q, expected 'ssh-dss'", signame);
	sigblob := siga[1].getbytes();
	if(len sigblob != 2*160/8)
		return "bad signature blob for ssh-dss";

	srvdsar := IPint.bytestoip(sigblob[:20]);
	srvdsas := IPint.bytestoip(sigblob[20:]);

	dsapk := ref DSApk (srvdsap.getipint(), srvdsaq.getipint(), srvdsag.getipint(), srvdsay.getipint());
	dsasig := ref DSAsig (srvdsar, srvdsas);
	dsamsg := IPint.bytestoip(sha1(h));
	ok := dsapk.verify(dsasig, dsamsg);
	if(!ok)
		return "dsa hash signature does not match";
	return nil;
}


packpacket(c: ref Sshc, m: ref Tssh): array of byte
{
	if(m.packed != nil)
		return m.packed;

	if(dflag) say(sprint("packpacket, t %d", m.t));

	m.seq = c.outseq++;
	if(c.outseq >= Seqmax)
		c.outseq = big 0;

	k := c.tosrv;
	pktunit := max(Packetunitmin, k.crypt.bsize);
	minpktlen := max(Pktlenmin, m.minpktlen);

	size := 4+1;  # pktlen, padlen
	size += 1;  # type
	for(i := 0; i < len m.v; i++)
		size += m.v[i].size();

	padlen := pktunit - size % pktunit;
	if(padlen < Padmin)
		padlen += pktunit;
	if(size+padlen < minpktlen)
		padlen += pktunit + pktunit * ((minpktlen-(size+padlen))/pktunit);
	size += padlen;
	if(dflag) say(sprint("packpacket, total buf %d, pktlen %d, padlen %d, maclen %d", size, size-4, padlen, k.mac.nbytes));

	d := array[size+k.mac.nbytes] of byte;

	o := 0;
	length := len d-k.mac.nbytes;
	o = p32i(d, o, length-4);
	d[o++] = byte padlen;
	d[o++] = byte m.t;
	for(i = 0; i < len m.v; i++)
		o += m.v[i].packbuf(d[o:]);
	d[o:] = random->randombuf(Random->NotQuiteRandom, padlen);
	o += padlen;
	if(o != length)
		raise "internal error packing message";

	if(k.mac.nbytes > 0) {
		seqbuf := array[4] of byte;
		p32(seqbuf, 0, m.seq);
		k.mac.hash(seqbuf::d[:len d-k.mac.nbytes]::nil, d[len d-k.mac.nbytes:]);
	}
	c.nkeypkts++;
	c.nkeybytes += big length;
	k.crypt.crypt(d, length, kr->Encrypt);
	return d;
}


ioerror(s: string)
{
	raise "io:"+s;
}

protoerror(s: string)
{
	raise "proto:"+s;
}

readpacket(c: ref Sshc): (ref Rssh, string, string)
{
	{
		return (xreadpacket(c), nil, nil);
	} exception x {
	"io:*" =>
		return (nil, x[len "io:":], nil);
	"proto:*" =>
		return (nil, nil, x[len "proto:":]);
	}
}

xreadpacket(c: ref Sshc): ref Rssh
{
	say("readpacket");

	k := c.fromsrv;
	pktunit := max(Packetunitmin, k.crypt.bsize);

	lead := array[pktunit] of byte;
	n := c.b.read(lead, len lead);
	if(n < 0)
		ioerror(sprint("read packet length: %r"));
	if(n != len lead)
		ioerror("short read for packet length");

	k.crypt.crypt(lead, len lead, kr->Decrypt);

	pktlen := g32i(lead, 0).t0;
	padlen := int lead[4];
	paylen := pktlen-1-padlen;
	if(dflag) say(sprint("readpacket, pktlen %d, padlen %d, paylen %d, maclen %d", pktlen, padlen, paylen, k.mac.nbytes));

	if(4+pktlen+k.mac.nbytes > Pktlenmax)
		protoerror(sprint("packet too large: 4+pktlen %d+maclen %d > pktlenmax %d", pktlen, k.mac.nbytes, Pktlenmax));
	if((4+pktlen) % pktunit != 0)
		protoerror(sprint("bad padding, 4+pktlen %d %% pktunit %d = %d (!= 0)", pktlen, pktunit, (4+pktlen) % pktunit));
	if(4+pktlen < Pktlenmin)
		protoerror(sprint("packet too small: 4+pktlen %d < Packetmin %d", pktlen, Pktlenmin));

	if(paylen <= 0)
		protoerror(sprint("payload too small: paylen %d <= 0", paylen));
	if(padlen < Padmin)
		protoerror(sprint("padding too small: padlen %d < Padmin %d", padlen, Padmin));

	total := array[4+pktlen+k.mac.nbytes] of byte;
	total[:] = lead;
	rem := total[len lead:];

	n = c.b.read(rem, len rem);
	if(n < 0)
		ioerror(sprint("read payload: %r"));
	if(n != len rem)
		ioerror("short read for payload");

	k.crypt.crypt(rem, len rem-k.mac.nbytes, kr->Decrypt);

	if(k.mac.nbytes> 0) {
		# mac = MAC(key, sequence_number || unencrypted_packet)
		seqbuf := array[4] of byte;
		p32(seqbuf, 0, c.inseq);

		pktdigest := total[len total-k.mac.nbytes:];
		calcdigest := array[k.mac.nbytes] of byte;
		k.mac.hash(seqbuf::total[:len total-k.mac.nbytes]::nil, calcdigest);
		if(!eq(calcdigest, pktdigest))
			protoerror(sprint("bad packet signature, have %s, expected %s", hex(pktdigest), hex(calcdigest)));
	}

	m := ref Rssh (c.inseq, 0, total[4+1:len total-padlen-k.mac.nbytes]);
	m.t = int m.buf[0];
	
	c.inseq++;
	if(c.inseq >= Seqmax)
		c.inseq = big 0;
	c.nkeypkts++;
	c.nkeybytes += big (len lead+len rem-k.mac.nbytes);

	return m;
}


Tssh.text(m: self ref Tssh): string
{
	return sprint("%q (%d)", msgname(m.t), m.t);
}

Rssh.text(m: self ref Rssh): string
{
	return sprint("%q (%d)", msgname(m.t), m.t);
}

Sshc.kexbusy(c: self ref Sshc): int
{
	return c.kexstate & (Kexinitsent|Kexinitreceived|Newkeyssent|Newkeysreceived|Havenewkeys);
}


Cryptalg.new(t: int): ref Cryptalg
{
	case t {
	Enone =>	return ref Cryptalg.None (8, 0);
	Eaes128cbc =>	return ref Cryptalg.Aes (kr->AESbsize, 128, nil);
	Eaes192cbc =>	return ref Cryptalg.Aes (kr->AESbsize, 192, nil);
	Eaes256cbc =>	return ref Cryptalg.Aes (kr->AESbsize, 256, nil);
	Eblowfish =>	return ref Cryptalg.Blowfish (kr->BFbsize, 128, nil);  # broken!
	Eidea =>	return ref Cryptalg.Idea (kr->IDEAbsize, 128, nil);
	Earcfour =>	return ref Cryptalg.Arcfour (8, 128, nil);
	E3descbc =>	return ref Cryptalg.Tripledes (kr->DESbsize, 192, nil, nil);  # 168 bits are used
	Eaes128ctr =>	return ref Cryptalg.Aesctr (kr->AESbsize, 128, nil, nil);
	Eaes192ctr =>	return ref Cryptalg.Aesctr (kr->AESbsize, 192, nil, nil);
	Eaes256ctr =>	return ref Cryptalg.Aesctr (kr->AESbsize, 256, nil, nil);
	Earcfour128 =>	return ref Cryptalg.Arcfour2 (8, 128, nil);
	Earcfour256 =>	return ref Cryptalg.Arcfour2 (8, 256, nil);
	}
	raise "missing case";
}

Cryptalg.news(name: string): ref Cryptalg
{
	t := xindex(knownenc, name);
	return Cryptalg.new(t);
}

Cryptalg.setup(cc: self ref Cryptalg, key, ivec: array of byte)
{
	pick c := cc {
	None =>	;
	Aes =>		c.state = kr->aessetup(key, ivec);
	Blowfish =>	c.state = kr->blowfishsetup(key, ivec); # broken!
	Idea =>		c.state = kr->ideasetup(key, ivec);
	Arcfour =>	c.state = kr->rc4setup(key);
	Tripledes =>
		c.states = array[] of {
			kr->dessetup(key[0:8], nil),
			kr->dessetup(key[8:16], nil),
			kr->dessetup(key[16:24], nil)
		};
		c.iv = ivec[:8];
	Aesctr =>
		c.counter = array[kr->AESbsize] of byte;
		c.counter[:] = ivec[:kr->AESbsize];
		c.key = array[len key] of byte;
		c.key[:] = key;
	Arcfour2 =>
		c.state = kr->rc4setup(key);
		c.crypt(array[1536] of byte, 1536, kr->Encrypt);
	}
}

Cryptalg.crypt(cc: self ref Cryptalg, buf: array of byte, n, direction: int)
{
	pick c := cc {
	None =>	;
	Aes =>		kr->aescbc(c.state, buf, n, direction);
	Blowfish =>	kr->blowfishcbc(c.state, buf, n, direction); # broken!
	Idea =>		kr->ideacbc(c.state, buf, n, direction);
	Arcfour or
	Arcfour2  =>	kr->rc4(c.state, buf, n);
	Tripledes =>
		buf = buf[:n];
		while(len buf > 0) {
			block := buf[:kr->DESbsize];
			if(direction == kr->Encrypt) {
				bufxor(block, c.iv);
				kr->desecb(c.states[0], block, len block, kr->Encrypt);
				kr->desecb(c.states[1], block, len block, kr->Decrypt);
				kr->desecb(c.states[2], block, len block, kr->Encrypt);
				c.iv[:] = block;
				buf = buf[len block:];
			} else {
				orig := array[len block] of byte;
				orig[:] = block;
				kr->desecb(c.states[2], block, len block, kr->Decrypt);
				kr->desecb(c.states[1], block, len block, kr->Encrypt);
				kr->desecb(c.states[0], block, len block, kr->Decrypt);
				bufxor(block, c.iv);
				c.iv[:] = orig;
				buf = buf[len block:];
			}
		}
	Aesctr =>
		key := array[kr->AESbsize] of byte;
		for(o := 0; o < n; o += kr->AESbsize) {
			key[:] = c.counter;

			# can we just keep a copy of the state after setup?  so we have to do it only once
			state := kr->aessetup(c.key, array[kr->AESbsize] of {* => byte 0});
			kr->aescbc(state, key, kr->AESbsize, kr->Encrypt);

			block := buf[o:min(n, o+kr->AESbsize)];
			bufxor(block, key);
			bufincr(c.counter);
		}
	}
}

bufxor(dst, key: array of byte)
{
	for(i := 0; i < len dst; i++)
		dst[i] ^= key[i];
}

bufincr(d: array of byte)
{
	for(i := len d-1; i >= 0; i--)
		if(++d[i] != byte 0)
			break;
}


Macalg.new(t: int): ref Macalg
{
	case t {
	Mnone =>	return ref Macalg.None (0, 0, nil);
	Msha1 =>	return ref Macalg.Sha1 (kr->SHA1dlen, kr->SHA1dlen, nil);
	Msha1_96 =>	return ref Macalg.Sha1_96 (96/8, kr->SHA1dlen, nil);
	Mmd5 =>		return ref Macalg.Md5 (kr->MD5dlen, kr->MD5dlen, nil);
	Mmd5_96 =>	return ref Macalg.Md5_96 (96/8, kr->MD5dlen, nil);
	* =>	raise "missing case";
	}
}

Macalg.news(name: string): ref Macalg
{
	t := xindex(knownmac, name);
	return Macalg.new(t);
}

Macalg.setup(mm: self ref Macalg, key: array of byte)
{
	mm.key = key[:mm.keybytes];
}

Macalg.hash(mm: self ref Macalg, bufs: list of array of byte, hash: array of byte)
{
	pick m := mm {
	None =>
		return;
	Sha1 or
	Sha1_96 =>
		state: ref DigestState;
		digest := array[kr->SHA1dlen] of byte;
		for(; bufs != nil; bufs = tl bufs)
			state = kr->hmac_sha1(hd bufs, len hd bufs, m.key, nil, state);
		kr->hmac_sha1(nil, 0, m.key, digest, state);
		hash[:] = digest[:m.nbytes];
	Md5 or
	Md5_96 =>
		state: ref DigestState;
		digest := array[kr->MD5dlen] of byte;
		for(; bufs != nil; bufs = tl bufs)
			state = kr->hmac_md5(hd bufs, len hd bufs, m.key, nil, state);
		kr->hmac_md5(nil, 0, m.key, digest, state);
		hash[:] = digest[:m.nbytes];
	* =>
		raise "missing case";
	}
}


Keys.new(cfg: ref Cfg): (ref Keys, ref Keys)
{
	a := ref Keys (Cryptalg.news(hd cfg.encout), Macalg.news(hd cfg.macout));
	b := ref Keys (Cryptalg.news(hd cfg.encin), Macalg.news(hd cfg.macin));
	return (a, b);
}

algnames(aa: array of string, ta: array of int): list of string
{
	l: list of string;
	for(i := len ta-1; i >= 0; i--)
		l = aa[ta[i]]::l;
	return l;
}

Cfg.default(): ref Cfg
{
	kex := algnames(knownkex, defkex);
	hostkey := algnames(knownhostkey, defhostkey);
	enc := algnames(knownenc, defenc);
	mac := algnames(knownmac, defmac);
	compr := algnames(knowncompr, defcompr);
	authmeth := algnames(knownauthmeth, defauthmeth);
	return ref Cfg ("", kex, hostkey, enc, enc, mac, mac, compr, compr, authmeth);
}

Cfg.set(c: self ref Cfg, t: int, l: list of string): string
{
	knowns := array[] of {
		knownkex,
		knownhostkey,
		knownenc,
		knownmac,
		knowncompr,
		knownauthmeth,
	};
	known := knowns[t];
	if(l == nil)
		return "list empty";

next:
	for(n := l; n != nil; n = tl n) {
		for(i := 0; i < len known; i++)
			if(known[i] == hd n)
				continue next;
		return "unsupported: "+hd n;
	}
	case t {
	Akex =>		c.kex = l;
	Ahostkey =>	c.hostkey = l;
	Aenc =>		c.encin = c.encout = l;
	Amac =>		c.macin = c.macout = l;
	Acompr =>	c.comprin = c.comprout = l;
	Aauthmeth =>	c.authmeth = l;
	}
	return nil;
}

Cfg.setopt(c: self ref Cfg, ch: int, s: string): string
{
	t: int;
	case ch {
	'K' =>	t = Akex;
	'H' =>	t = Ahostkey;
	'e' =>	t = Aenc;
	'm' =>	t = Amac;
	'C' =>	t = Acompr;
	'A' =>	t = Aauthmeth;
	'k' =>	c.keyspec = s;
		return nil;
	* =>	return "unrecognized ssh config option";
	}
	(l, err) := parsenames(s);
	if(err == nil)
		err = c.set(t, l);
	return err;
}

Nomatch: exception(string);
firstmatch(name: string, a, b: list of string): list of string raises Nomatch
{
	for(; a != nil; a = tl a)
		for(l := b; l != nil; l = tl l)
			if(hd a == hd l)
				return hd a::nil;
	raise Nomatch(sprint("no match for %q", name));
}

Cfg.match(client, server: ref Cfg): (ref Cfg, string)
{
	n := ref Cfg;
	{
		n.kex = firstmatch("kex exchange", client.kex, server.kex);
		n.hostkey = firstmatch("server host key", client.hostkey, server.hostkey);
		n.encout = firstmatch("encryption to server", client.encout, server.encout);
		n.encin = firstmatch("encryption from server", client.encin, server.encin);
		n.macout = firstmatch("mac to server", client.macout, server.macout);
		n.macin = firstmatch("mac from server", client.macin, server.macin);
		n.comprout = firstmatch("compression to server", client.comprout, server.comprout);
		n.comprin = firstmatch("compression from server", client.comprin, server.comprin);
	}exception e{
	Nomatch =>
		return (nil, e);
	}
	n.keyspec = client.keyspec;
	n.authmeth = client.authmeth;
	return (n, nil);
}


Cfg.text(c: self ref Cfg): string
{
	s := "config:";
	s += "\n\tkey exchange: "+join(c.kex, ",");
	s += "\n\tserver host key: "+join(c.hostkey, ",");
	s += "\n\tencryption to server: "+join(c.encout, ",");
	s += "\n\tencryption from server: "+join(c.encin, ",");
	s += "\n\tmac to server: "+join(c.macout, ",");
	s += "\n\tmac from server: "+join(c.macin, ",");
	s += "\n\tcompression to server: "+join(c.comprout, ",");
	s += "\n\tcompression from server: "+join(c.comprin, ",");
	s += "\n";
	return s;
}

parsenames(s: string): (list of string, string)
{
	l: list of string;
	e: string;
	while(s != nil) {
		(e, s) = str->splitstrl(s, ",");
		if(e == nil)
			return (nil, "malformed list");
		l = e::l;
		if(s != nil)
			s = s[1:];
	}
	return (l, nil);
}

authmethods(l: list of string): list of string
{
	r: list of string;
	for(; l != nil; l = tl l)
		case hd l {
		"publickey" =>
			r = "dsa"::"rsa"::r;
		"password" =>
			r = "password"::r;
		}
	return rev(r);
}

xindex(a: array of string, s: string): int
{
	for(i := 0; i < len a; i++)
		if(a[i] == s)
			return i;
	raise "missing value";
}

zero(d: array of byte)
{
	d[:] = array[len d] of {* => byte 0};
}

sha1many(l: list of array of byte): array of byte
{
	st: ref Keyring->DigestState;
	for(; l != nil; l = tl l)
		st = kr->sha1(hd l, len hd l, nil, st);
	kr->sha1(nil, 0, h := array[Keyring->SHA1dlen] of byte, st);
	return h;
}

md5(d: array of byte): array of byte
{
	h := array[Keyring->MD5dlen] of byte;
	kr->md5(d, len d, h, nil);
	return h;
}

sha1(d: array of byte): array of byte
{
	h := array[Keyring->SHA1dlen] of byte;
	kr->sha1(d, len d, h, nil);
	return h;
}

fingerprint(d: array of byte): string
{
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint(":%02x", int d[i]);
	if(s != nil)
		s = s[1:];
	return s;
}

say(s: string)
{
	if(dflag)
		warn(s);
}
