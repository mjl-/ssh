implement Sshlib;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "string.m";
	str: String;
include "lists.m";
	lists: Lists;
include "security.m";
	random: Random;
include "keyring.m";
	kr: Keyring;
	IPint, RSAsk, RSApk, RSAsig, DSAsk, DSApk, DSAsig, DigestState: import kr;
include "factotum.m";
	fact: Factotum;
include "encoding.m";
	base16, base64: Encoding;
include "sshlib.m";

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

# what we want to do by default, first is preferred
defkex :=	array[] of {Dgroupexchange, Dgroup14, Dgroup1};
defhostkey :=	array[] of {Hrsa, Hdss};
defenc :=	array[] of {Eaes128cbc, Eaes192cbc, Eaes256cbc, Eaes128ctr, Eaes192ctr, Eaes256ctr, Earcfour128, Earcfour256, Earcfour};
defmac :=	array[] of {Msha1_96, Msha1, Mmd5, Mmd5_96};
defcompr :=	array[] of {Cnone};

Padmin:	con 4;
Packetmin:	con 16;
Pktlenmax:	con 35000;
Dhexchangemin:	con 1*1024;
Dhexchangewant:	con 1*1024;  # 2*1024 is recommended, but it is too slow
Dhexchangemax:	con 8*1024;

Kex: adt {
	new:	int;
	dhgroup:	ref Dh;
	e, x:	ref IPint;
};

Dh: adt {
	prime, gen:	ref IPint;
	nbits:	int;
};
dhgroup1, dhgroup14: ref Dh;


init()
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	bufio->open("/dev/null", Bufio->OREAD);
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	random = load Random Random->PATH;
	kr = load Keyring Keyring->PATH;
	base16 = load Encoding Encoding->BASE16PATH;
	base64 = load Encoding Encoding->BASE64PATH;
	fact = load Factotum Factotum->PATH;
	fact->init();

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

login(fd: ref Sys->FD, addr: string, cfg: ref Cfg): (ref Sshc, string)
{
	b := bufio->fopen(fd, Bufio->OREAD);
	if(b == nil)
		return (nil, sprint("bufio fopen: %r"));

	lident := "SSH-2.0-inferno0";
	if(sys->fprint(fd, "%s\r\n", lident) < 0)
		return (nil, sprint("write: %r"));
	(rident, err) := getline(b);
	if(err != nil)
		return (nil, err);
	# xxx lines that don't look like an ident string should be ignored and another line read
	(rversion, rname, rerr) := parseident(rident);
	if(rerr != nil)
		return (nil, rerr);
	if(rversion != "2.0" && rversion != "1.99")
		return (nil, sprint("bad remote version %#q", rversion));
	say(sprint("connected, remote version %#q, name %#q", rversion, rname));

	nilkey := ref Keys (Cryptalg.new(Enone), Macalg.new(Enone));
	c := ref Sshc (fd, b, addr, cfg.keyspec, 0, 0, nilkey, nilkey, nil, nil, lident, rident, cfg, nil);

	nilnames := valnames(nil);
	cookie := random->randombuf(Random->NotQuiteRandom, 16);
	a := array[] of {
		valbuf(cookie),
		valnames(cfg.kex),
		valnames(cfg.hostkey),
		valnames(cfg.encout), valnames(cfg.encin),
		valnames(cfg.macout), valnames(cfg.macin),
		valnames(cfg.comprout), valnames(cfg.comprin),
		nilnames, nilnames,
		valbool(0),
		valint(0),
	};

	clkexinit, srvkexinit: array of byte;  # packets, for use in hash in dh exchange

	kexinitpkt := packpacket(c, SSH_MSG_KEXINIT, a, 0);
	err = writebuf(c, kexinitpkt);
	if(err != nil)
		return (nil, err);
	say("wrote kexinit packet");
	kexpad := int kexinitpkt[4];
	clkexinit = kexinitpkt[5:len kexinitpkt-kexpad];

	kex: ref Kex;
	case hd cfg.kex {
	"diffie-hellman-group1-sha1" =>
		kex = ref Kex (0, dhgroup1, nil, nil);
	"diffie-hellman-group14-sha1" =>
		kex = ref Kex (0, dhgroup14, nil, nil);
	"diffie-hellman-group-exchange-sha1" =>
		kex = ref Kex (1, nil, nil, nil);
	* =>
		return (nil, "unrecognized key exchange algorithm");
	}

	for(;;) {
		(d, perr) := readpacket(c);
		if(perr != nil)
			return (nil, perr);

		say(sprint("packet, payload length %d, type %d", len d, int d[0]));

		case int d[0] {
		SSH_MSG_DISCONNECT =>
			cmd("### msg disconnect");
			discmsg := list of {Tint, Tstr, Tstr};
			(a, err) = parsepacket(d[1:], discmsg);
			if(err != nil) {
				warn(err);
				continue;
			}
			say("reason: "+a[0].text());
			say("descr: "+a[1].text());
			say("language: "+a[2].text());
			return (nil, "disconnected");

		SSH_MSG_KEXINIT =>
			cmd("### msg kexinit");
			kexmsg := list of {16, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tbool, Tint};
			(a, err) = parsepacket(d[1:], kexmsg);
			if(err != nil) {
				warn(err);
				continue;
			}
			srvkexinit = d;
			o := 1;
			remcfg := ref Cfg (
				nil,
				getnames(a[o++]),
				getnames(a[o++]),
				getnames(a[o++]), getnames(a[o++]),
				getnames(a[o++]), getnames(a[o++]),
				getnames(a[o++]), getnames(a[o++])
			);
			say("languages client to server: "+a[o++].text());
			say("languages server to client: "+a[o++].text());
			say("first kex packet follows: "+a[o++].text());
			say("out config:\n"+cfg.text());
			say("from remote:\n"+remcfg.text());
			usecfg: ref Cfg;
			(usecfg, err) = Cfg.match(cfg, remcfg);
			if(err != nil)
				return (nil, err);
			say("chosen config:\n"+usecfg.text());
			(c.newtosrv, c.newfromsrv) = Keys.new(usecfg);

			msgt: int;
			msg: array of ref Val;
			if(kex.new) {
				msg = array[] of {valint(Dhexchangemin), valint(Dhexchangewant), valint(Dhexchangemax)};
				msgt = SSH_MSG_KEX_DH_GEX_REQUEST;
			} else {
				gendh(kex);
				msg = array[] of {valmpint(kex.e)};
				msgt = SSH_MSG_KEXDH_INIT;
			}
			err = writepacket(c, msgt, msg);
			if(err != nil)
				return (nil, err);

		SSH_MSG_NEWKEYS =>
			cmd("### msg newkeys");
			(nil, err) = parsepacket(d[1:], nil);
			if(err != nil)
				return (nil, "bad newkeys packet");
			say("server wants to use newkeys");
			err = writepacket(c, SSH_MSG_NEWKEYS, nil);
			if(err != nil)
				return (nil, "writing newkeys: "+err);
			say("now using new keys");
			c.tosrv = c.newtosrv;
			c.fromsrv = c.newfromsrv;
			c.newtosrv = c.newfromsrv = nil;

			# byte      SSH_MSG_SERVICE_REQUEST
			# string    service name
			a = array[] of {valstr("ssh-userauth")};
			err = writepacket(c, SSH_MSG_SERVICE_REQUEST, a);
			if(err != nil)
				return (nil, err);

		SSH_MSG_KEXDH_INIT to SSH_MSG_KEXDH_GEX_REQUEST =>
			t := int d[0];

			if(kex.new && t == SSH_MSG_KEX_DH_GEX_REPLY || !kex.new && t == SSH_MSG_KEXDH_REPLY) {
				cmd("### msg kexdh reply");
				#kexdhreplmsg := list of {Tmpint, Tmpint};  # for group exchange?
				kexdhreplmsg := list of {Tstr, Tmpint, Tstr};
				(a, err) = parsepacket(d[1:], kexdhreplmsg);
				#string    server public host key and certificates (K_S)
				#mpint     f
				#string    signature of H
				if(err != nil)
					return (nil, err);

				srvksval := a[0];
				srvfval := a[1];
				srvks := getbytes(srvksval);
				srvf := getipint(srvfval);
				srvsigh := getbytes(a[2]);

				# C then
				# computes K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S
				# || e || f || K), and verifies the signature s on H.
				say("calculating key from f from remote");
				key := srvf.expmod(kex.x, kex.dhgroup.prime);
				say("have key");
				kex.x = nil;
				#say(sprint("key %s", key.iptostr(16)));
				hashbufs: list of array of byte;
				if(kex.new)
					hashbufs = list of {
						valstr(lident).pack(),
						valstr(rident).pack(),
						valbytes(clkexinit).pack(),
						valbytes(srvkexinit).pack(),
						srvksval.pack(),
						valint(Dhexchangemin).pack(),
						valint(Dhexchangewant).pack(),
						valint(Dhexchangemax).pack(),
						valmpint(kex.dhgroup.prime).pack(),
						valmpint(kex.dhgroup.gen).pack(),
						valmpint(kex.e).pack(),
						srvfval.pack(),
						valmpint(key).pack()
					};
				else
					hashbufs = list of {
						valstr(lident).pack(),
						valstr(rident).pack(),
						valbytes(clkexinit).pack(),
						valbytes(srvkexinit).pack(),
						srvksval.pack(),
						valmpint(kex.e).pack(),
						srvfval.pack(),
						valmpint(key).pack()
					};
				dhhash := sha1many(hashbufs);
				zero(clkexinit);
				clkexinit = nil;
				zero(srvkexinit);
				srvkexinit = nil;
				srvfval = nil;

				say(sprint("hash on dh %s", fingerprint(dhhash)));
				c.sessionid = dhhash;

				err = verifyhostkey(hd cfg.hostkey, srvks, srvsigh, dhhash);
				if(err != nil)
					return (nil, err);

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

				ivc2s := genkey(keybitsout, keypack, dhhash, "A", dhhash);
				ivs2c := genkey(keybitsin, keypack, dhhash, "B", dhhash);
				enckeyc2s := genkey(keybitsout, keypack, dhhash, "C", dhhash);
				enckeys2c := genkey(keybitsin, keypack, dhhash, "D", dhhash);
				mackeyc2s := genkey(macbitsout, keypack, dhhash, "E", dhhash);
				mackeys2c := genkey(macbitsin, keypack, dhhash, "F", dhhash);

				say("ivc2s "+hex(ivc2s));
				say("ivs2c "+hex(ivs2c));
				say("enckeyc2s "+hex(enckeyc2s));
				say("enckeys2c "+hex(enckeys2c));
				say("mackeyc2s "+hex(mackeyc2s));
				say("mackeys2c "+hex(mackeys2c));

				c.newtosrv.crypt.setup(enckeyc2s, ivc2s);
				c.newfromsrv.crypt.setup(enckeys2c, ivs2c);
				c.newtosrv.mac.setup(mackeyc2s);
				c.newfromsrv.mac.setup(mackeys2c);
			} else if(kex.new && t == SSH_MSG_KEX_DH_GEX_GROUP) {
				cmd("### dex dh gex group");
				(a, err) = parsepacket(d[1:], list of {Tmpint, Tmpint});
				if(err != nil)
					return (nil, err);
				prime := getipint(a[0]);
				gen := getipint(a[1]);
				# xxx should verify these values are sane.
				kex.dhgroup = ref Dh (prime, gen, prime.bits());

				gendh(kex);

				msg := array[] of {valmpint(kex.e)};
				err = writepacket(c, SSH_MSG_KEX_DH_GEX_INIT, msg);
				if(err != nil)
					return (nil, err);
			} else {
				return (nil, sprint("unexpected kex message, t %d, new %d", t, kex.new));
			}

		SSH_MSG_IGNORE =>
			cmd("### msg ignore");
			(a, err) = parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				return (nil, "msg ignore: "+err);
			say("msg ignore, data: "+getstr(a[0]));

			a = array[] of {valstr("test!")};
			err = writepacket(c, SSH_MSG_IGNORE, a);
			if(err != nil)
				return (nil, err);

		SSH_MSG_SERVICE_ACCEPT =>
			cmd("### msg service accept");
			# byte      SSH_MSG_SERVICE_ACCEPT
			# string    service name
			(a, err) = parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				return (nil, err);
			say("service accepted: "+a[0].text());

			err = pubkeyrsa(c);
			if(err != nil)
				err = pubkeydsa(c);
			if(err != nil)
				err = passwordauth(c);
			if(err != nil)
				return (nil, err);

		SSH_MSG_DEBUG =>
			cmd("### msg debug");
			# byte      SSH_MSG_DEBUG
			# boolean   always_display
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = parsepacket(d[1:], list of {Tbool, Tstr, Tstr});
			if(err != nil)
				return (nil, err);
			warn("remote debug: "+getstr(a[1]));

		SSH_MSG_UNIMPLEMENTED =>
			cmd("### msg unimplemented");
			# byte      SSH_MSG_UNIMPLEMENTED
			# uint32    packet sequence number of rejected message
			(a, err) = parsepacket(d[1:], list of {Tint});
			if(err != nil)
				return (nil, err);
			pktno := getint(a[0]);
			say(sprint("packet %d is not implemented at remote...", pktno));

		SSH_MSG_USERAUTH_FAILURE =>
			cmd("### msg userauth failure");
			# byte         SSH_MSG_USERAUTH_FAILURE
			# name-list    authentications that can continue
			# boolean      partial success
			(a, err) = parsepacket(d[1:], list of {Tnames, Tbool});
			if(err != nil)
				return (nil, err);
			warn("auth failure");
			say(sprint("other auth methods that can be tried: %s", a[0].text()));
			say(sprint("partical succes %s", a[1].text()));
			return (nil, "bad auth");

		SSH_MSG_USERAUTH_SUCCESS =>
			cmd("### msg userauth successful");
			# byte      SSH_MSG_USERAUTH_SUCCESS
			(a, err) = parsepacket(d[1:], nil);
			if(err != nil)
				return (nil, err);
			say("logged in!");
			return (c, nil);

		SSH_MSG_USERAUTH_BANNER =>
			cmd("### msg userauth banner");
			# byte      SSH_MSG_USERAUTH_BANNER
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = parsepacket(d[1:], list of {Tstr, Tstr});
			if(err != nil)
				return (nil, err);
			msg := getstr(a[0]);
			warn("auth banner: "+msg);

		* =>
			cmd(sprint("### other packet type %d", int d[0]));
		}
	}
}

gendh(k: ref Kex)
{
	# 1. C generates a random number x (1 < x < q) and computes
	# e = g^x mod p.  C sends e to S.
	say(sprint("gendh, nbits %d", k.dhgroup.nbits));
	k.x = IPint.random(k.dhgroup.nbits, k.dhgroup.nbits); # xxx sane params?
	say(sprint("k.x %s", k.x.iptostr(16)));
	k.e = k.dhgroup.gen.expmod(k.x, k.dhgroup.prime);
	say(sprint("k.e %s", k.e.iptostr(16)));
}

valbyte(v: byte): ref Val
{
	return ref Val.Byte (v);
}
valbool(v: int): ref Val
{
	return ref Val.Bool (v);
}
valint(v: int): ref Val
{
	return ref Val.Int (v);
}
valbig(v: big): ref Val
{
	return ref Val.Big (v);
}
valmpint(v: ref IPint): ref Val
{
	return ref Val.Mpint (v);
}
valnames(v: list of string): ref Val
{
	return ref Val.Names (v);
}
valstr(v: string): ref Val
{
	return ref Val.Str (array of byte v);
}
valbytes(v: array of byte): ref Val
{
	return ref Val.Str (v);
}
valbuf(v: array of byte): ref Val
{
	return ref Val.Buf (v);
}

getline(b: ref Iobuf): (string, string)
{
	l := b.gets('\n');
	if(l == nil)
		return (nil, "early eof");
	if(l[len l-1] != '\n')
		return (nil, "eof before newline");
	l = l[:len l-1];
	if(l != nil && l[len l-1] == '\r')
		l = l[:len l-1];
	return (l, nil);
}

cmd(s: string)
{
	say("\n"+s+"\n");
}


Cryptalg.new(t: int): ref Cryptalg
{
	case t {
	Enone =>	return ref Cryptalg.None (8, 0);
	Eaes128cbc =>	return ref Cryptalg.Aes (kr->AESbsize, 128, nil);
	Eaes192cbc =>	return ref Cryptalg.Aes (kr->AESbsize, 192, nil);
	Eaes256cbc =>	return ref Cryptalg.Aes (kr->AESbsize, 256, nil);
	Eblowfish =>	return ref Cryptalg.Blowfish (kr->BFbsize, 128, nil);
	Eidea =>	return ref Cryptalg.Idea (kr->IDEAbsize, 128, nil);
	Earcfour =>	return ref Cryptalg.Arcfour (8, 128, nil);
	Etripledes =>
		# of 192 bits, only 168 are used!
		#return ref Cryptalg.Tripledes (kr->DESbsize, 192, nil);
		raise "not yet implemented";
	Eaes128ctr =>	return ref Cryptalg.Aesctr (kr->AESbsize, 128, nil, nil);
	Eaes192ctr =>	return ref Cryptalg.Aesctr (kr->AESbsize, 192, nil, nil);
	Eaes256ctr =>	return ref Cryptalg.Aesctr (kr->AESbsize, 256, nil, nil);
	Earcfour128 =>	return ref Cryptalg.Arcfour2 (8, 128, nil);
	Earcfour256 =>	return ref Cryptalg.Arcfour2 (8, 256, nil);
	}
	raise "missing case";
}

xindex(a: array of string, s: string): int
{
	for(i := 0; i < len a; i++)
		if(a[i] == s)
			return i;
	raise "missing value";
}

Cryptalg.news(name: string): ref Cryptalg
{
	t := xindex(knownenc, name);
	return Cryptalg.new(t);
}

genkey(needbits: int, k, h: array of byte, x: string, sessionid: array of byte): array of byte
{
	nbytes := needbits/8;
	say(sprint("genkey, needbits %d, nbytes %d", needbits, nbytes));
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
		ks = lists->reverse(kx::lists->reverse(ks));
	}
	return key[:nbytes];
}

Cryptalg.setup(cc: self ref Cryptalg, key, ivec: array of byte)
{
	pick c := cc {
	None =>	;
	Aes =>		c.state = kr->aessetup(key, ivec);
	Blowfish =>	c.state = kr->blowfishsetup(key, ivec);
	Idea =>		c.state = kr->ideasetup(key, ivec);
	Arcfour =>	c.state = kr->rc4setup(key);
	Tripledes =>	raise "not yet implemented";
	Aesctr =>
		c.counter = array[kr->AESbsize] of byte;
		c.counter[:] = ivec[:kr->AESbsize];
		#say("aesctr x:");
		#hexdump(c.x);

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
	Blowfish =>	kr->blowfishcbc(c.state, buf, n, direction);
	Idea =>		kr->ideacbc(c.state, buf, n, direction);
	Arcfour or
	Arcfour2  =>	kr->rc4(c.state, buf, n);
	Tripledes =>	raise "not yet implemented";
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
	Sha1 or Sha1_96 =>
		state: ref DigestState;
		digest := array[kr->SHA1dlen] of byte;
		for(; bufs != nil; bufs = tl bufs)
			state = kr->hmac_sha1(hd bufs, len hd bufs, m.key, nil, state);
		kr->hmac_sha1(nil, 0, m.key, digest, state);
		hash[:] = digest[:m.nbytes];
	Md5 or Md5_96 =>
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

passwordauth(c: ref Sshc): string
{
	#byte      SSH_MSG_USERAUTH_REQUEST
	#string    user name
	#string    service name
	#string    "password"
	#boolean   FALSE
	#string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
	(user, pass) := fact->getuserpasswd(sprint("proto=pass server=%q service=ssh %s", c.addr, c.keyspec));
	say("writing userauth request");
	vals := array[] of {
		valstr(user),
		valstr("ssh-connection"),
		valstr("password"),
		valbool(0),
		valstr(pass),
	};
	return writepacketpad(c, SSH_MSG_USERAUTH_REQUEST, vals, 100);
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

pubkeyrsa(c: ref Sshc): string
{
	say("doing pubkeyrsa");

	fd := sys->open("/mnt/factotum/rpc", Sys->ORDWR);
	if(fd == nil)
		return sprint("open factotum: %r");
	(v, a) := fact->rpc(fd, "start", sys->aprint("proto=rsa role=client addr=%q %s", c.addr, c.cfg.keyspec));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);  # xxx should probably try all keys available.  needs some code.
	if(v != "ok")
		return sprint("factotum: %s: %s", v, string a);
	(rsaepubs, rsans) := str->splitstrl(string a, " ");
	if(rsans == nil)
		return "bad response for rsa keys from factotum";
	rsans = rsans[1:];
	rsaepub := IPint.strtoip(rsaepubs, 16);
	rsan := IPint.strtoip(rsans, 16);
	say(sprint("from factotum, rsaepub %s, rsan %s", rsaepub.iptostr(16), rsan.iptostr(16)));

	# our public key
	pkvals := array[] of {
		valstr("ssh-rsa"),
		valmpint(rsaepub),
		valmpint(rsan),
	};
	pkblob := packvals(pkvals, 0);

	# data to sign
	sigdatvals := array[] of {
		valbytes(c.sessionid),
		valbyte(byte SSH_MSG_USERAUTH_REQUEST),
		valstr("sshtest"),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-rsa"),
		valbytes(pkblob),
	};
	sigdatblob := packvals(sigdatvals, 0);

	# sign it
	say("rsa hash: "+fingerprint(sha1(sigdatblob)));
	sigmsg := rsasha1msg(sigdatblob, rsan.bits()/8);
	sigm := IPint.bebytestoip(sigmsg);
	say(sprint("mp to sign: %s", sigm.iptostr(16)));

	(v, a) = fact->rpc(fd, "write", array of byte base16->enc(sigmsg));
	say(sprint("wrote messasge to sign to factotum, resp %q", v));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);
	if(v != "ok")
		return sprint("factotum: %s: %s", v, string a);
	say(sprint("response: %s", string a));
	sigbuf := base16->dec(string a);

	sigvals := array[] of {valstr("ssh-rsa"), valbytes(sigbuf)};
	sig := packvals(sigvals, 0);

	authvals := array[] of {
		valstr("sshtest"),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-rsa"),
		valbytes(pkblob),
		valbytes(sig),
	};
	return writepacket(c, SSH_MSG_USERAUTH_REQUEST, authvals);
}


pubkeydsa(c: ref Sshc): string
{
	say("doing pubkeydsa");

	fd := sys->open("/mnt/factotum/rpc", Sys->ORDWR);
	if(fd == nil)
		return sprint("open factotum: %r");
	(v, a) := fact->rpc(fd, "start", sys->aprint("proto=dsa role=client addr=%q %s", c.addr, c.cfg.keyspec));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);  # xxx should probably try all keys available.  needs some code.
	if(v != "ok")
		return sprint("factotum: %s: %s", v, string a);
	pkl := sys->tokenize(string a, " ").t1;
	if(len pkl != 4)
		return "bad response for public dsa key from factotum";
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
	pkblob := packvals(pkvals, 0);

	# data to sign
	sigdatvals := array[] of {
		valbytes(c.sessionid),
		valbyte(byte SSH_MSG_USERAUTH_REQUEST),
		valstr("sshtest"),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-dss"),
		valbytes(pkblob),
	};
	sigdatblob := packvals(sigdatvals, 0);

	# sign it
	(v, a) = fact->rpc(fd, "write", array of byte base16->enc(sha1(sigdatblob)));
	if(v == "ok")
		(v, a) = fact->rpc(fd, "read", nil);
	if(v != "ok")
		return sprint("factotum: %s: %s", v, string a);
	sigtoks := sys->tokenize(string a, " ").t1;
	sigbuf := array[20+20] of {* => byte 0};
	rbuf := base16->dec(hd sigtoks);
	sbuf := base16->dec(hd tl sigtoks);
	sigbuf[20-len rbuf:] = rbuf;
	sigbuf[40-len sbuf:] = sbuf;
	#hexdump(sigbuf);

	# the signature to put in the auth request packet
	sigvals := array[] of {valstr("ssh-dss"), valbytes(sigbuf)};
	sig := packvals(sigvals, 0);

	authvals := array[] of {
		valstr("sshtest"),
		valstr("ssh-connection"),
		valstr("publickey"),
		valbool(1),
		valstr("ssh-dss"),
		valbytes(pkblob),
		valbytes(sig),
	};
	return writepacket(c, SSH_MSG_USERAUTH_REQUEST, authvals);
}

verifyhostkey(name: string, ks, sig, h: array of byte): string
{
	case name {
	"ssh-rsa" =>	return verifyrsa(ks, sig, h);
	"ssh-dss" =>	return verifydss(ks, sig, h);
	}
	raise "missing case";
}

verifyrsa(ks, sig, h: array of byte): string
{
	# ssh-rsa host key:
	#string    "ssh-rsa"
	#mpint     e
	#mpint     n

	(keya, err) := parsepacket(ks, list of {Tstr, Tmpint, Tmpint});
	if(err != nil)
		return "bad ssh-rsa host key: "+err;
	signame := getstr(keya[0]);
	if(signame != "ssh-rsa")
		return sprint("host key not ssh-rsa, but %q", signame);
	srvrsae := keya[1];
	srvrsan := keya[2];
	say(sprint("server rsa key, e %s, n %s", srvrsae.text(), srvrsan.text()));
	rsan := getipint(srvrsan);
	rsae := getipint(srvrsae);

	say("rsa fingerprint: "+fingerprint(md5(ks)));

	# signature
	# string    "ssh-rsa"
	# string    rsa_signature_blob
	siga := keya;
	(siga, err) = parsepacket(sig, list of {Tstr, Tstr});
	if(err != nil)
		return "bad ssh-rsa signature: "+err;
	signame = getstr(siga[0]);
	if(signame != "ssh-rsa")
		return sprint("signature not ssh-rsa, but %q", signame);
	sigblob := getbytes(siga[1]);
	#say("sigblob:");
	#hexdump(sigblob);

	rsapk := ref RSApk (rsan, rsae);
	sigmsg := rsasha1msg(h, rsan.bits()/8);
	rsasig := ref RSAsig (IPint.bebytestoip(sigblob));
	ok := rsapk.verify(rsasig, IPint.bebytestoip(sigmsg));
	if(!ok)
		return "rsa signature does not match";
	return nil;
}

equal(a, b: array of byte): int
{
	if(len a != len b)
		return 0;
	for(i := 0; i < len a; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

verifydss(ks, sig, h: array of byte): string
{
	# string    "ssh-dss"
	# mpint     p
	# mpint     q
	# mpint     g
	# mpint     y

	(keya, err) := parsepacket(ks, list of {Tstr, Tmpint, Tmpint, Tmpint, Tmpint});
	if(err != nil)
		return "bad ssh-dss host key: "+err;
	if(getstr(keya[0]) != "ssh-dss")
		return sprint("host key not ssh-dss, but %q", getstr(keya[0]));
	srvdssp := keya[1];
	srvdssq := keya[2];
	srvdssg := keya[3];
	srvdssy := keya[4];
	say(sprint("server dss key, p %s, q %s, g %s, y %s", srvdssp.text(), srvdssq.text(), srvdssg.text(), srvdssy.text()));
	say("dss fingerprint: "+fingerprint(md5(ks)));


	# string    "ssh-dss"
	# string    dss_signature_blob

	#   The value for 'dss_signature_blob' is encoded as a string containing
	#   r, followed by s (which are 160-bit integers, without lengths or
	#   padding, unsigned, and in network byte order).
	siga := keya;
	(siga, err) = parsepacket(sig, list of {Tstr, Tstr});
	if(err != nil)
		return "bad ssh-dss signature: "+err;
	signame := getstr(siga[0]);
	if(signame != "ssh-dss")
		return sprint("signature not ssh-dss, but %q", signame);
	sigblob := getbytes(siga[1]);
	if(len sigblob != 2*160/8) {
		say(sprint("sigblob, length %d", len sigblob));
		hexdump(sigblob);
		return "bad signature blob for ssh-dss";
	}
	srvdssr := IPint.bytestoip(sigblob[:20]);
	srvdsss := IPint.bytestoip(sigblob[20:]);
	say(sprint("signature on dss, r %s, s %s", srvdssr.iptostr(16), srvdsss.iptostr(16)));

	dsapk := ref DSApk (getipint(srvdssp), getipint(srvdssq), getipint(srvdssg), getipint(srvdssy));
	dsasig := ref DSAsig (srvdssr, srvdsss);
	dsamsg := IPint.bytestoip(sha1(h));
	say(sprint("dsamsg, %s", dsamsg.iptostr(16)));
	ok := dsapk.verify(dsasig, dsamsg);
	if(!ok)
		return "dsa hash signature does not match";
	say("dsa hash signature matches");
	return nil;
}


## reading/writing/parsing packets

parseident(s: string): (string, string, string)
{
	if(len s > 255)
		return (nil, nil, "ident too long");
	origs := s;
	if(!str->prefix("SSH-", s))
		return (nil, nil, sprint("bad ident, probably not ssh: %q", origs));
	s = s[4:];
	(version, rem) := str->splitstrl(s, "-");
	if(rem == nil)
		return (nil, nil, sprint("missing software version: %q", origs));
	rem = rem[1:];
	(name, comment) := str->splitstrl(rem, " ");
	if(comment != nil)
		comment = comment[1:];
	return (version, name, nil);
}

packvals(a: array of ref Val, withlength: int): array of byte
{
	lensize := 0;
	if(withlength)
		lensize = 4;

	size := 0;
	for(i := 0; i < len a; i++)
		size += a[i].size();

	buf := array[lensize+size] of byte;
	if(withlength)
		p32(buf, size);

	o := lensize;
	for(i = 0; i < len a; i++)
		o += a[i].packbuf(buf[o:]);
	if(o != len buf)
		raise "packerror";
	return buf;
}

packpacket(c: ref Sshc, t: int, a: array of ref Val, minpktlen: int): array of byte
{
	k := c.tosrv;

	size := 4+1;  # pktlen, padlen
	size += 1;  # type
	for(i := 0; i < len a; i++)
		size += a[i].size();

	padlen := k.crypt.bsize - size % k.crypt.bsize;
	if(padlen < 4)
		padlen += k.crypt.bsize;
	if(size+padlen < minpktlen)
		padlen += k.crypt.bsize + k.crypt.bsize * ((minpktlen-(size+padlen))/k.crypt.bsize);
	size += padlen;
	say(sprint("packpacket, total buf %d, pktlen %d, padlen %d, maclen %d", size, size-4, padlen, k.mac.nbytes));

	d := array[size+k.mac.nbytes] of byte;

	o := 0;
	p32(d[o:], len d-k.mac.nbytes-4);  # length
	o += 4;
	d[o++] = byte padlen;  # pad length

	d[o++] = byte t;
	for(i = 0; i < len a; i++) {
		inc := a[i].packbuf(d[o:]);
		if(a[i].size() != inc)
			raise "blah";
		#say(sprint("elem, o %d, size %d, text %s", o, inc, a[i].text()));
		o += inc;
	}
	d[o:] = random->randombuf(Random->NotQuiteRandom, padlen);  # xxx reallyrandom is way too slow for me on inferno on openbsd
	o += padlen;
	say(sprint("o %d, len d %d", o, len d));
	if(o != len d-k.mac.nbytes)
		raise "error packing message";

	if(k.mac.nbytes > 0) {
		seqbuf := array[4] of byte;
		p32(seqbuf, c.outseq);
		k.mac.hash(seqbuf::d[:len d-k.mac.nbytes]::nil, d[len d-k.mac.nbytes:]);
	}
	c.outseq++;
	k.crypt.crypt(d, len d-k.mac.nbytes, kr->Encrypt);
	return d;
}

writepacketpad(c: ref Sshc, t: int, a: array of ref Val, minpktlen: int): string
{
	d := packpacket(c, t, a, minpktlen);
	return writebuf(c, d);
}

writepacket(c: ref Sshc, t: int, a: array of ref Val): string
{
	d := packpacket(c, t, a, 0);
	return writebuf(c, d);
}

writebuf(c: ref Sshc, d: array of byte): string
{
	n := sys->write(c.fd, d, len d);
	if(n != len d)
		return sprint("write: %r");
	return nil;
}

readpacket(c: ref Sshc): (array of byte, string)
{
	say("readpacket");

	k := c.fromsrv;

	lead := array[k.crypt.bsize] of byte;
	n := c.b.read(lead, len lead);
	if(n < 0)
		return (nil, sprint("read packet length: %r"));
	if(n != len lead)
		return (nil, "short read for packet length");

	k.crypt.crypt(lead, len lead, kr->Decrypt);

	pktlen := g32(lead);
	padlen := int lead[4];
	paylen := pktlen-1-padlen;
	say(sprint("readpacket, pktlen %d, padlen %d, paylen %d, maclen %d", pktlen, padlen, paylen, k.mac.nbytes));

	if(pktlen > Pktlenmax)
		return (nil, sprint("packet too large: %d", pktlen));
	if((4+pktlen) % k.crypt.bsize != 0)
		return (nil, sprint("bad padding, length %d, blocksize %d, pad %d, mod %d", 4+pktlen, k.crypt.bsize, padlen, (4+pktlen) % k.crypt.bsize));

	if(paylen <= 0)
		return (nil, "bad paylen");
	if(padlen < Padmin)
		return (nil, "bad padlen");

	total := array[4+pktlen+k.mac.nbytes] of byte;
	total[:] = lead;
	rem := total[len lead:];

	n = c.b.read(rem, len rem);
	if(n < 0)
		return (nil, sprint("read payload: %r"));
	if(n != len rem)
		return (nil, "short read for payload");

	k.crypt.crypt(rem, len rem-k.mac.nbytes, kr->Decrypt);

	# mac = MAC(key, sequence_number || unencrypted_packet)
	if(k.mac.nbytes> 0) {
		seqbuf := array[4] of byte;
		p32(seqbuf, c.inseq);

		digest := array[k.mac.nbytes] of byte;
		k.mac.hash(seqbuf::total[:len total-len digest]::nil, digest);
		ldig := hex(digest);
		pdig := hex(total[len total-k.mac.nbytes:]);
		#say(sprint("calc digest %s", ldig));
		#say(sprint("pkt digest %s", pdig));
		if(ldig != pdig)
			return (nil, sprint("bad signature, have %s, expected %s", pdig, ldig));
	}
	c.inseq++;

	return (total[5:len total-padlen-k.mac.nbytes], nil);
}


ebread(b: ref Iobuf, want: int): array of byte
{
	have := b.read(d := array[want] of byte, len d);
	if(have < 0)
		raise sprint("ebread:read %r");
	if(have != len d)
		raise sprint("ebread:short read, have %d, wanted %d", have, want);
	return d;
}

bparsepacket(b: ref Iobuf, l: list of int): (array of ref Val, string)
{
	{
		return parsepacket0(b, nil, l);
	} exception e {
	"ebread:*" =>
		return (nil, e[len "ebread:":]);
	}
}

parsepacket(buf: array of byte, l: list of int): (array of ref Val, string)
{
	return parsepacket0(nil, buf, l);
}

parsepacket0(b: ref Iobuf, buf: array of byte, l: list of int): (array of ref Val, string)
{
	r: list of ref Val;
	o := 0;
	i := 0;
	for(; l != nil; l = tl l) {
		#say(sprint("parse, %d elems left, %d bytes left", len l, len buf-o));
		t := hd l;
		if(b != nil)
			case t {
			Tbyte =>	buf = ebread(b, 1);
			Tbool =>	buf = ebread(b, 1);
			Tint =>		buf = ebread(b, 4);
			Tbig =>		buf = ebread(b, 8);
			Tnames or Tstr or Tmpint =>	buf = ebread(b, 4);
			* =>
				if(t > 0)
					buf = ebread(b, t);
			}
		
		case t {
		Tbyte =>
			if(o+1 > len buf)
				return (nil, "short buffer for byte");
			r = ref Val.Byte (buf[o++])::r;
		Tbool =>
			if(o+1 > len buf)
				return (nil, "short buffer for byte");
			r = ref Val.Bool (int buf[o++])::r;
		Tint =>
			if(o+4 > len buf)
				return (nil, "short buffer for int");
			r = ref Val.Int (g32(buf[o:]))::r;
			o += 4;
		Tbig =>
			if(o+8 > len buf)
				return (nil, "short buffer for big");
			r = ref Val.Big (g64(buf[o:]))::r;
			o += 8;
		Tnames or Tstr or Tmpint =>
			if(o+4 > len buf)
				return (nil, "short buffer for int for length");
			length := g32(buf[o:]);
			o += 4;
			if(b != nil) {
				buf = ebread(b, length);
				o = 0;
			}
			if(o+length > len buf)
				return (nil, "short buffer for name-list/string/mpint");
			case t {
			Tnames =>
				# xxx disallow non-printable?
				# xxx better verify tokens
				r = ref Val.Names (sys->tokenize(string buf[o:o+length], ",").t1)::r;
			Tstr =>
				r = ref Val.Str (buf[o:o+length])::r;
			Tmpint =>
				#say(sprint("read mpint of length %d", length));
				if(length == 0) {
					r = valmpint(IPint.strtoip("0", 10))::r;
				} else {
					neg := 0;
					if(int buf[o] & 16r80) {
						raise "negative incoming";
						neg = 1;
						buf[o] &= byte 16r7f;
					}
					v := IPint.bebytestoip(buf[o:o+length]);
					if(neg) {
						buf[o] |= byte 16r80;
						v = v.neg();
					}
					r = valmpint(v)::r;
					#say(sprint("new mpint %s", (hd r).text()));
				}
			}
			o += length;
		* =>
			if(t < 0)
				return (nil, sprint("unknown type %d requested", t));
			if(o+t > len buf)
				return (nil, "short buffer for byte-array");
			r = ref Val.Str (buf[o:o+t])::r;
			o += t;
		}
		#say(sprint("new val, size %d, text %s", (hd r).size(), (hd r).text()));
		i++;
	}
	if(o != len buf)
		return (nil, sprint("leftover data in buffer, %d bytes", len buf-o));
	return (l2a(lists->reverse(r)), nil);
}

hexdump(buf: array of byte)
{
	s := "";
	i := 0;
	while(i < len buf) {
		for(j := 0; j < 16 && i < len buf; j++) {
			if((i & 1) == 0)
				s += " ";
			s += sprint("%02x", int buf[i]);
			i++;
		}
		s += "\n";
	}
	say(s);
}

hexdumpbufs(l: list of array of byte)
{
	size := 0;
	for(a := l; a != nil; a = tl a)
		size += len hd a;
	buf := array[size] of byte;
	o := 0;
	for(a = l; a != nil; a = tl a) {
		buf[o:] = hd a;
		o += len hd a;
	}
	hexdump(buf);
}

sha1many(l: list of array of byte): array of byte
{
	state: ref Keyring->DigestState;
	for(; l != nil; l = tl l)
		state = kr->sha1(hd l, len hd l, nil, state);
	kr->sha1(nil, 0, h := array[Keyring->SHA1dlen] of byte, state);
	return h;
}


## misc functions

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
	if(len d == 0)
		return "";
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint(":%02x", int d[i]);
	return s[1:];
}

hex(d: array of byte): string
{
	if(len d == 0)
		return "";
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint(" %02x", int d[i]);
	return s[1:];
}


getbyte(v: ref Val): byte
{
	pick vv := v {
	Byte =>	return byte vv.v;
	}
	raise "not byte";
}

getbool(v: ref Val): int
{
	pick vv := v {
	Bool =>	return vv.v;
	}
	raise "not bool";
}

getint(v: ref Val): int
{
	pick vv := v {
	Int =>	return vv.v;
	}
	raise "not int";
}

getbig(v: ref Val): big
{
	pick vv := v {
	Big =>	return vv.v;
	}
	raise "not big";
}

getnames(v: ref Val): list of string
{
	pick vv := v {
	Names =>	return vv.l;
	}
	raise "not names";
}

getipint(v: ref Val): ref IPint
{
	pick vv := v {
	Mpint =>	return vv.v;
	}
	raise "not mpint";
}

getstr(v: ref Val): string
{
	pick vv := v {
	Str =>	return string vv.buf;
	}
	raise "not string";
}

getbytes(v: ref Val): array of byte
{
	pick vv := v {
	Str =>	return vv.buf;
	}
	raise "not string (bytes)";
}


## val

Val.pack(v: self ref Val): array of byte
{
	n := v.size();
	d := array[n] of byte;
	v.packbuf(d);
	return d;
}

Val.text(vv: self ref Val): string
{
	pick v := vv {
	Byte =>	return string v.v;
	Bool =>
		if(v.v)
			return "true";
		return "false";
	Int =>	return string v.v;
	Big =>	return string v.v;
	Names =>	return join(v.l, ",");
	Str =>	return "string "+string v.buf;
	Mpint =>
		return "ipint "+v.v.iptostr(16);
	Buf =>	return "buf "+string v.buf;
	}
}

Val.size(vv: self ref Val): int
{
	pick v := vv {
	Byte =>	return 1;
	Bool =>	return 1;
	Int =>	return 4;
	Big =>	return 8;
	Names =>	return 4+len join(v.l, ",");
	Str =>	return 4+len v.buf;
	Mpint =>	return len packmpint(v.v);
	Buf =>	return len v.buf;
	}
}

packmpint(v: ref IPint): array of byte
{
	zero := IPint.strtoip("0", 10);
	cmp := zero.cmp(v);
	if(cmp == 0) {
		d := array[4] of byte;
		p32(d, 0);
		return d;
	}
	if(v.cmp(zero) < 0)
		raise "negative";
	buf := v.iptobebytes();
	if(int buf[0] & 16r80) {
		nbuf := array[len buf+1] of byte;
		nbuf[0] = byte 0;
		nbuf[1:] = buf;
		buf = nbuf;
	}
	d := array[4+len buf] of byte;
	p32(d, len buf);
	d[4:] = buf;
	#say(sprint("Val.Mpint.pack, hex %s", hex(d)));
	return d;
}

Val.packbuf(vv: self ref Val, d: array of byte): int
{
	pick v := vv {
	Byte =>
		d[0] = v.v;
		return 1;
	Bool =>
		d[0] = byte v.v;
		return 1;
	Int =>
		p32(d, v.v);
		return 4;
	Big =>
		p64(d, v.v);
		return 8;
	Names =>
		s := array of byte join(v.l, ",");
		p32(d, len s);
		d[4:] = s;
		return 4+len s;
	Str =>
		p32(d, len v.buf);
		d[4:] = v.buf;
		return 4+len v.buf;
	Mpint =>
		buf := packmpint(v.v);
		d[:] = buf;
		return len buf;
	Buf =>
		d[:] = v.buf;
		return len v.buf;
	};
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
	return ref Cfg ("", kex, hostkey, enc, enc, mac, mac, compr, compr);
}

Cfg.set(c: self ref Cfg, t: int, l: list of string): string
{
	knowns := array[] of {
		knownkex,
		knownhostkey,
		knownenc,
		knownmac,
		knowncompr,
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
	'k' =>	c.keyspec = s;
		return nil;
	* =>	return "unrecognized ssh config option";
	}
	(l, err) := parsenames(s);
	if(err == nil)
		err = c.set(t, l);
	return err;
}

firstmatch(name: string, a, b: list of string, err: string): (list of string, string)
{
	if(err != nil)
		return (nil, err);
	for(; a != nil; a = tl a)
		for(l := b; l != nil; l = tl l)
			if(hd a == hd l)
				return (hd a::nil, nil);
	return (nil, sprint("no match for %q", name));
}

Cfg.match(client, server: ref Cfg): (ref Cfg, string)
{
	err: string;
	n := ref Cfg;
	(n.kex, err) = firstmatch("kex exchange", client.kex, server.kex, err);
	(n.hostkey, err) = firstmatch("server host key", client.hostkey, server.hostkey, err);
	(n.encout, err) = firstmatch("encryption to server", client.encout, server.encout, err);
	(n.encin, err) = firstmatch("encryption from server", client.encin, server.encin, err);
	(n.macout, err) = firstmatch("mac to server", client.macout, server.macout, err);
	(n.macin, err) = firstmatch("mac from server", client.macin, server.macin, err);
	(n.comprout, err) = firstmatch("compression to server", client.comprout, server.comprout, err);
	(n.comprin, err) = firstmatch("compression from server", client.comprin, server.comprin, err);
	if(err != nil)
		return (nil, err);
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


# misc

p32(d: array of byte, v: int)
{
	d[0] = byte (v>>24);
	d[1] = byte (v>>16);
	d[2] = byte (v>>8);
	d[3] = byte (v>>0);
}

p64(d: array of byte, v: big)
{
	p32(d, int (v>>32));
	p32(d[4:], int v);
}

g32(d: array of byte): int
{
	v := 0;
	v = v<<8|int d[0];
	v = v<<8|int d[1];
	v = v<<8|int d[2];
	v = v<<8|int d[3];
	return v;
}

g64(d: array of byte): big
{
	return big g32(d)<<32|big g32(d[4:]);
}

join(l: list of string, sep: string): string
{
	if(l == nil)
		return "";
	s := "";
	for(; l != nil; l = tl l)
		s += sep+hd l;
	return s[len sep:];
}


l2a[T](l: list of T): array of T
{
	a := array[len l] of T;
	i := 0;
	for(; l != nil; l = tl l)
		a[i++] = hd l;
	return a;
}

min(a, b: int): int
{
	if(a < b)
		return a;
	return b;
}

zero(d: array of byte)
{
	d[:] = array[len d] of {* => byte 0};
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "sshlib: %s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}
