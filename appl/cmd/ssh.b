implement Ssh;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "lists.m";
	lists: Lists;
include "string.m";
	str: String;
include "keyring.m";
	kr: Keyring;
	IPint, RSApk, RSAsig: import kr;
include "security.m";
	random: Random;
include "sshlib.m";
	sshlib: Sshlib;
	Sshc, Keys, Val: import sshlib;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshlib;
	getstr, getmpint, getint: import sshlib;
	mpintpack, hex, hexfp: import sshlib;

Ssh: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	kr = load Keyring Keyring->PATH;
	random = load Random Random->PATH;
	sshlib = load Sshlib Sshlib->PATH;
	sshlib->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] addr");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	addr := hd args;

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	b := bufio->fopen(conn.dfd, Bufio->OREAD);

	lident := "SSH-2.0-inferno0";
	c := ref Sshc (conn.dfd, b, 0, 0, nil, nil);
	if(sys->fprint(c.fd, "%s\r\n", lident) < 0)
		fail(sprint("write: %r"));
	(rident, err) := getline(c.b);
	if(err != nil)
		fail(err);
	# xxx lines that don't look like an ident string should be ignored and another line read
	(rversion, rname, rerr) := sshlib->parseident(rident);
	if(rerr != nil)
		fail(rerr);
	if(rversion != "2.0" && rversion != "1.99")
		fail(sprint("bad remote version %#q", rversion));
	say(sprint("connected, remote version %#q, name %#q", rversion, rname));

	nilnames := ref Val.Names;
	cookie := array[16] of {* => byte 2};
	knownkexnames := ref Val.Names (a2l(knownkex));
	knownhostkeynames := ref Val.Names (a2l(knownhostkey));
	knownencnames := ref Val.Names (a2l(knownenc));
	knownmacnames := ref Val.Names (a2l(knownmac));
	knowncomprnames := ref Val.Names (a2l(knowncompr));
	a := array[] of {
		ref Val.Buf (cookie),
		knownkexnames,
		knownhostkeynames,
		knownencnames, knownencnames,
		knownmacnames, knownmacnames,
		knowncomprnames, knowncomprnames,
		nilnames, nilnames,
		ref Val.Bool (0),
		ref Val.Int (0),
	};

	clkexinit, srvkexinit: array of byte;  # packets, for use in hash in dh exchange

	kexinitpkt := sshlib->packpacket(c, Sshlib->SSH_MSG_KEXINIT, a);
	err = sshlib->writebuf(c, kexinitpkt);
	if(err != nil)
		fail(err);
	say("wrote kexinit packet");
	kexpad := int kexinitpkt[4];
	clkexinit = kexinitpkt[5:len kexinitpkt-kexpad];

	dhprimestr := 
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF";
	dhprime := IPint.strtoip(dhprimestr, 16);
	if(dhprime == nil) raise "prime";
	dhgen := IPint.strtoip("2", 10);
	dhq := 2048;
	dhe, dhipx: ref IPint;
	sharedkey: ref IPint;
	sessionhash: array of byte;

	newtosrv: ref Keys;
	newfromsrv: ref Keys;

	for(;;) {
		(d, perr) := sshlib->readpacket(c);
		if(perr != nil)
			fail(perr);

		say(sprint("packet, payload length %d, type %d", len d, int d[0]));

		case int d[0] {
		Sshlib->SSH_MSG_DISCONNECT =>
			cmd("### msg disconnect");
			discmsg := list of {Tint, Tstr, Tstr};
			(a, err) = sshlib->parsepacket(d[1:], discmsg);
			if(err != nil) {
				warn(err);
				continue;
			}
			say("reason: "+a[0].text());
			say("descr: "+a[1].text());
			say("language: "+a[2].text());
			return;

		Sshlib->SSH_MSG_KEXINIT =>
			cmd("### msg kexinit");
			kexmsg := list of {16, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tbool, Tint};
			(a, err) = sshlib->parsepacket(d[1:], kexmsg);
			if(err != nil) {
				warn(err);
				continue;
			}
			srvkexinit = d;
			o := 1;
			say("key exchange: "+a[o++].text());
			say("server host key: "+a[o++].text());
			say("encrypton client to server: "+a[o++].text());
			say("encryption server to client: "+a[o++].text());
			say("mac client to server: "+a[o++].text());
			say("mac server to client: "+a[o++].text());
			say("compression client to server: "+a[o++].text());
			say("compression server to client: "+a[o++].text());
			say("languages client to server: "+a[o++].text());
			say("languages server to client: "+a[o++].text());
			say("first kex packet follows: "+a[o++].text());


			# 1. C generates a random number x (1 < x < q) and computes
			# e = g^x mod p.  C sends e to S.
			# xxx use   random:    fn(minbits, maxbits: int): ref IPint;
			dhx := getrand(2, dhq);
			say(sprint("dhx %d", dhx));
			dhipx = IPint.strtoip(string dhx, 10);
			dhe = dhgen.expmod(dhipx, dhprime);
			say(sprint("dhe %s", dhe.iptostr(16)));

			#e := ref Val.Mpint (IPint.strtoip("12343", 10));
			msg := array[1] of ref Val;
			#msg[0] = ref Val.Int (2048);
			msg[0] = ref Val.Mpint (dhe);
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_KEXDH_INIT, msg);
			if(err != nil)
				fail(err);

		Sshlib->SSH_MSG_NEWKEYS =>
			cmd("### msg newkeys");
			(nil, err) = sshlib->parsepacket(d[1:], nil);
			if(err != nil)
				fail("bad newkeys packet");
			say("server wants to use newkeys");
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_NEWKEYS, nil);
			if(err != nil)
				fail("writing newkeys: "+err);
			say("now using new keys");
			c.tosrv = newtosrv;
			c.fromsrv = newfromsrv;

		Sshlib->SSH_MSG_KEXDH_REPLY =>
			cmd("### msg kexdh reply");
			#kexdhreplmsg := list of {Tmpint, Tmpint};  # for group exchange?
			kexdhreplmsg := list of {Tstr, Tmpint, Tstr};
			(a, err) = sshlib->parsepacket(d[1:], kexdhreplmsg);
			#string    server public host key and certificates (K_S)
			#mpint     f
			#string    signature of H
			if(err != nil)
				fail(err);
			say(sprint("have SSH_MSG_KEXDH_REPLY, v1 %s, v2 %s, v3 %s", a[0].text(), a[1].text(), a[2].text()));

			srvksval := a[0];
			srvfval := a[1];
			srvks := getstr(srvksval);
			srvf := getmpint(srvfval);
			srvsigh := getstr(a[2]);

			# ssh-rsa host key:
			#string    "ssh-rsa"
			#mpint     e
			#mpint     n

			keya := a;
			(keya, err) = sshlib->parsepacket(srvks, list of {Tstr, Tmpint, Tmpint});
			if(err != nil)
				fail("bad ssh-rsa host key");
			if(string getstr(keya[0]) != "ssh-rsa")
				fail(sprint("host key not ssh-rsa, but %q", string getstr(keya[0])));
			srvrsae := keya[1];
			srvrsan := keya[2];
			say(sprint("server rsa key, e %s, n %s", srvrsae.text(), srvrsan.text()));

			say("rsa fingerprint: "+hexfp(sshlib->md5(srvks)));

			# signature
			# string    "ssh-rsa"
			# string    rsa_signature_blob
			siga := a;
			(siga, err) = sshlib->parsepacket(srvsigh, list of {Tstr, Tstr});
			if(err != nil)
				fail("bad ssh-rsa signature");
			signame := getstr(siga[0]);
			if(string signame != "ssh-rsa")
				fail(sprint("signature not ssh-rsa, but %q", string signame));
			sigblob := getstr(siga[1]);
			sign := IPint.bytestoip(sigblob);
			say("sigblob:");
			sshlib->hexdump(sigblob);
			say(sprint("signature %s", sign.iptostr(16)));


			# C then
			# computes K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S
			# || e || f || K), and verifies the signature s on H.
			say(sprint("using lident %q, rident %q", lident, rident));
			key := srvf.expmod(dhipx, dhprime);
			sharedkey = key;
			say(sprint("key %s", key.iptostr(16)));
			dhhash := sshlib->sha1bufs(list of {
				(ref Val.Str (array of byte lident)).pack(),
				(ref Val.Str (array of byte rident)).pack(),
				(ref Val.Str (clkexinit)).pack(),
				(ref Val.Str (srvkexinit)).pack(),
				srvksval.pack(),
				mpintpack(dhe),
				srvfval.pack(),
				mpintpack(key)});
			say(sprint("hash on dh %s", hexfp(dhhash)));
			sessionhash = dhhash;

			rsasig := ref RSAsig (sign); # n
			rsapk := ref RSApk (getmpint(srvrsan), getmpint(srvrsae)); # n, ek
			rsamsg := IPint.bebytestoip(dhhash);
			say(sprint("rsasig %s", sign.iptostr(16)));
			say(sprint("rsamsg %s", rsamsg.iptostr(16)));
			ok = rsapk.verify(rsasig, rsamsg);
			# xxx this fails for now.  rsasig is wrong.  we can't just directly use the signature, it's an asn.1 thing (i think) that we have to parse.  perhaps there's a sha1 in it that we have to use.
			if(ok == 0)
				warn("rsa signature on dh exchange doesn't match");

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

			keypack := (ref Val.Mpint(key)).pack();
			ivc2s := sshlib->sha1bufs(list of {keypack, dhhash, array of byte "A", dhhash});
			ivs2c := sshlib->sha1bufs(list of {keypack, dhhash, array of byte "B", dhhash});
			enckeyc2s := sshlib->sha1bufs(list of {keypack, dhhash, array of byte "C", dhhash});
			enckeys2c := sshlib->sha1bufs(list of {keypack, dhhash, array of byte "D", dhhash});
			intkeyc2s := sshlib->sha1bufs(list of {keypack, dhhash, array of byte "E", dhhash});
			intkeys2c := sshlib->sha1bufs(list of {keypack, dhhash, array of byte "F", dhhash});

			say("ivc2s "+hex(ivc2s));
			say("ivs2c "+hex(ivs2c));
			say("enckeyc2s "+hex(enckeyc2s));
			say("enckeys2c "+hex(enckeys2c));
			say("intkeyc2s "+hex(intkeyc2s));
			say("intkeys2c "+hex(intkeys2c));

			statec2s := kr->aessetup(enckeyc2s[:16], ivc2s[:16]);
			states2c := kr->aessetup(enckeys2c[:16], ivs2c[:16]);
			newtosrv = ref Keys (statec2s, Keyring->AESbsize, intkeyc2s[:20]);
			newfromsrv = ref Keys (states2c, Keyring->AESbsize, intkeys2c[:20]);

		Sshlib->SSH_MSG_IGNORE =>
			cmd("### msg ignore");
			(a, err) = sshlib->parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				fail("msg ignore: "+err);
			say("msg ignore, data: "+string getstr(a[0]));

			a = array[1] of ref Val;
			a[0] = ref Val.Str (array of byte "test!");
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_IGNORE, a);
			if(err != nil)
				fail(err);

			# xxx obviously wrong place, but openssh sshd won't send more after this (when compiled with debug mode)

			# byte      SSH_MSG_SERVICE_REQUEST
			# string    service name
			a = array[1] of ref Val;
			a[0] = ref Val.Str (array of byte "ssh-userauth");
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_SERVICE_REQUEST, a);
			if(err != nil)
				fail(err);

		Sshlib->SSH_MSG_SERVICE_ACCEPT =>
			cmd("### msg service accept");
			# byte      SSH_MSG_SERVICE_ACCEPT
			# string    service name
			(a, err) = sshlib->parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				fail(err);
			say("service accepted: "+a[0].text());

			#byte      SSH_MSG_USERAUTH_REQUEST
			#string    user name
			#string    service name
			#string    "password"
			#boolean   FALSE
			#string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
			say("writing userauth request");
			user := username();
			passwd := getpass();
			vals := array[] of {
				ref Val.Str(array of byte user),
				ref Val.Str(array of byte "ssh-connection"),
				ref Val.Str(array of byte "password"),
				ref Val.Bool(0),
				ref Val.Str(array of byte passwd),
			};
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_USERAUTH_REQUEST, vals);
			if(err != nil)
				fail(err);

		Sshlib->SSH_MSG_DEBUG =>
			cmd("### msg debug");
			# byte      SSH_MSG_DEBUG
			# boolean   always_display
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = sshlib->parsepacket(d[1:], list of {Tbool, Tstr, Tstr});
			if(err != nil)
				fail(err);
			warn("remote debug: "+string getstr(a[1]));

		Sshlib->SSH_MSG_UNIMPLEMENTED =>
			cmd("### msg unimplemented");
			# byte      SSH_MSG_UNIMPLEMENTED
			# uint32    packet sequence number of rejected message
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint});
			if(err != nil)
				fail(err);
			pktno := getint(a[0]);
			say(sprint("packet %d is not implemented at remote...", pktno));

		Sshlib->SSH_MSG_USERAUTH_FAILURE =>
			cmd("### msg userauth failure");
			# byte         SSH_MSG_USERAUTH_FAILURE
			# name-list    authentications that can continue
			# boolean      partial success
			(a, err) = sshlib->parsepacket(d[1:], list of {Tnames, Tbool});
			if(err != nil)
				fail(err);
			warn("auth failure");
			say(sprint("other auth methods that can be tried: %s", a[0].text()));
			say(sprint("partical succes %s", a[1].text()));
			fail("auth");

		Sshlib->SSH_MSG_USERAUTH_SUCCESS =>
			cmd("### msg userauth successful");
			# byte      SSH_MSG_USERAUTH_SUCCESS
			(a, err) = sshlib->parsepacket(d[1:], nil);
			if(err != nil)
				fail(err);
			warn("logged in!");

			# byte      SSH_MSG_CHANNEL_OPEN
			# string    channel type in US-ASCII only
			# uint32    sender channel
			# uint32    initial window size
			# uint32    maximum packet size
			# ....      channel type specific data follows
			vals := array[] of {
				ref Val.Str(array of byte "session"),
				ref Val.Int(0),
				ref Val.Int(1*1024*1024),
				ref Val.Int(32*1024),
			};
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, vals);
			if(err != nil)
				fail(err);

		Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
			cmd("### channel open confirmation");
			# byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
			# uint32    recipient channel
			# uint32    sender channel
			# uint32    initial window size
			# uint32    maximum packet size
			# ....      channel type specific data follows
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint, Tint, Tint, Tint});
			if(err != nil)
				fail(err);

			say("writing 'exec' channel request");
			# byte      SSH_MSG_CHANNEL_REQUEST
			# uint32    recipient channel
			# string    "exec"
			# boolean   want reply
			# string    command
			vals := array[] of {
				ref Val.Int (0),
				ref Val.Str (array of byte "exec"),
				ref Val.Bool (1),
				ref Val.Str (array of byte "date"),
			};
			err = sshlib->writepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			if(err != nil)
				fail(err);
			say("wrote request to execute command");

		Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
			cmd("### channel success");
			(nil, err) = sshlib->parsepacket(d[1:], list of {Tint});
			if(err != nil)
				fail(err);

		Sshlib->SSH_MSG_CHANNEL_FAILURE =>
			cmd("### channel failure");
			(nil, err) = sshlib->parsepacket(d[1:], list of {Tint});
			if(err != nil)
				fail(err);

		Sshlib->SSH_MSG_CHANNEL_DATA =>
			cmd("### channel data");
			# byte      SSH_MSG_CHANNEL_DATA
			# uint32    recipient channel
			# string    data
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint, Tstr});
			if(err != nil)
				fail(err);
			say("channel data:\n"+string getstr(a[1]));

		Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
			cmd("### channel extended data");
			# byte      SSH_MSG_CHANNEL_EXTENDED_DATA
			# uint32    recipient channel
			# uint32    data_type_code
			# string    data
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint, Tint, Tstr});
			if(err != nil)
				fail(err);
			datatype := getint(a[1]);
			case datatype {
			Sshlib->SSH_EXTENDED_DATA_STDERR =>
				say("stderr");
				warn("data: "+string getstr(a[2]));
			* =>
				warn("extended data but not stderr?");
			}

		Sshlib->SSH_MSG_CHANNEL_EOF =>
			cmd("### channel eof");
			# byte      SSH_MSG_CHANNEL_EOF
			# uint32    recipient channel
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint});
			if(err != nil)
				fail(err);
			warn("channel done");

		Sshlib->SSH_MSG_CHANNEL_CLOSE =>
			cmd("### channel close");
			# byte      SSH_MSG_CHANNEL_CLOSE
			# uint32    recipient channel
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint});
			if(err != nil)
				fail(err);
			warn("channel closed");
			return;

		Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
			cmd("### channel open failure");
			# byte      SSH_MSG_CHANNEL_OPEN_FAILURE
			# uint32    recipient channel
			# uint32    reason code
			# string    description in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = sshlib->parsepacket(d[1:], list of {Tint, Tint, Tstr, Tstr});
			if(err != nil)
				fail(err);
			fail("channel open failure: "+string getstr(a[2]));

		Sshlib->SSH_MSG_USERAUTH_BANNER =>
			cmd("### msg userauth banner");
			# byte      SSH_MSG_USERAUTH_BANNER
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = sshlib->parsepacket(d[1:], list of {Tstr, Tstr});
			if(err != nil)
				fail(err);
			msg := string getstr(a[0]);
			warn("auth banner: "+msg);

		* =>
			cmd(sprint("### other packet type %d", int d[0]));
		}
	}
}

cmd(s: string)
{
	say("\n"+s+"\n");
}

getrand(min, max: int): int
{
	# xxx
	return 1797;
	v := min+random->randomint(Random->ReallyRandom)%(max-min);
	if(v < 0)
		v = -v;
	return v;
}

knownkex := array[] of {"diffie-hellman-group1-sha1"};
knownhostkey := array[] of {"ssh-rsa"};
knownenc := array[] of {"aes128-cbc"};
knownmac := array[] of {"hmac-sha1"};
knowncompr := array[] of {"none"};

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

getpass(): string
{
	return "testtest";
}

username(): string
{
	return "sshtest";
	fd := sys->open("/dev/user", Sys->OREAD);
	if(fd == nil)
		return "none";
	n := sys->read(fd, buf := array[32] of byte, len buf);
	if(n <= 0)
		return "none";
	return string buf[:n];
}

max(a, b: int): int
{
	if(a < b)
		return b;
	return a;
}

a2l[T](a: array of T): list of T
{
	l: list of T;
	for(i := len a-1; i >= 0; i--)
		l = a[i]::l;
	return l;
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	warn(s);
	raise "fail:"+s;
}
