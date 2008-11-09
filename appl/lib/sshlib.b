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
	IPint, RSApk, RSAsig: import kr;
include "factotum.m";
	fact: Factotum;
include "sshlib.m";

init()
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	bufio->open("/dev/null", Bufio->OREAD);
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	random = load Random Random->PATH;
	kr = load Keyring Keyring->PATH;
	fact = load Factotum Factotum->PATH;
	fact->init();
}


knownkex := array[] of {"diffie-hellman-group1-sha1"};
knownhostkey := array[] of {"ssh-rsa"};
knownenc := array[] of {"aes128-cbc"};
knownmac := array[] of {"hmac-sha1"};
knowncompr := array[] of {"none"};

login(fd: ref Sys->FD, addr: string): (ref Sshc, string)
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

	c := ref Sshc (fd, b, addr, 0, 0, nil, nil, lident, rident);

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

	kexinitpkt := packpacket(c, Sshlib->SSH_MSG_KEXINIT, a);
	err = writebuf(c, kexinitpkt);
	if(err != nil)
		return (nil, err);
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
		(d, perr) := readpacket(c);
		if(perr != nil)
			return (nil, perr);

		say(sprint("packet, payload length %d, type %d", len d, int d[0]));

		case int d[0] {
		Sshlib->SSH_MSG_DISCONNECT =>
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

		Sshlib->SSH_MSG_KEXINIT =>
			cmd("### msg kexinit");
			kexmsg := list of {16, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tnames, Tbool, Tint};
			(a, err) = parsepacket(d[1:], kexmsg);
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
			err = writepacket(c, Sshlib->SSH_MSG_KEXDH_INIT, msg);
			if(err != nil)
				return (nil, err);

		Sshlib->SSH_MSG_NEWKEYS =>
			cmd("### msg newkeys");
			(nil, err) = parsepacket(d[1:], nil);
			if(err != nil)
				return (nil, "bad newkeys packet");
			say("server wants to use newkeys");
			err = writepacket(c, Sshlib->SSH_MSG_NEWKEYS, nil);
			if(err != nil)
				return (nil, "writing newkeys: "+err);
			say("now using new keys");
			c.tosrv = newtosrv;
			c.fromsrv = newfromsrv;

		Sshlib->SSH_MSG_KEXDH_REPLY =>
			cmd("### msg kexdh reply");
			#kexdhreplmsg := list of {Tmpint, Tmpint};  # for group exchange?
			kexdhreplmsg := list of {Tstr, Tmpint, Tstr};
			(a, err) = parsepacket(d[1:], kexdhreplmsg);
			#string    server public host key and certificates (K_S)
			#mpint     f
			#string    signature of H
			if(err != nil)
				return (nil, err);
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
			(keya, err) = parsepacket(srvks, list of {Tstr, Tmpint, Tmpint});
			if(err != nil)
				return (nil, "bad ssh-rsa host key");
			if(string getstr(keya[0]) != "ssh-rsa")
				return (nil, sprint("host key not ssh-rsa, but %q", string getstr(keya[0])));
			srvrsae := keya[1];
			srvrsan := keya[2];
			say(sprint("server rsa key, e %s, n %s", srvrsae.text(), srvrsan.text()));

			say("rsa fingerprint: "+hexfp(md5(srvks)));

			# signature
			# string    "ssh-rsa"
			# string    rsa_signature_blob
			siga := a;
			(siga, err) = parsepacket(srvsigh, list of {Tstr, Tstr});
			if(err != nil)
				return (nil, "bad ssh-rsa signature");
			signame := getstr(siga[0]);
			if(string signame != "ssh-rsa")
				return (nil, sprint("signature not ssh-rsa, but %q", string signame));
			sigblob := getstr(siga[1]);
			sign := IPint.bytestoip(sigblob);
			say("sigblob:");
			hexdump(sigblob);
			say(sprint("signature %s", sign.iptostr(16)));


			# C then
			# computes K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S
			# || e || f || K), and verifies the signature s on H.
			say(sprint("using lident %q, rident %q", lident, rident));
			key := srvf.expmod(dhipx, dhprime);
			sharedkey = key;
			say(sprint("key %s", key.iptostr(16)));
			dhhash := sha1bufs(list of {
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
			ok := rsapk.verify(rsasig, rsamsg);
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
			ivc2s := sha1bufs(list of {keypack, dhhash, array of byte "A", dhhash});
			ivs2c := sha1bufs(list of {keypack, dhhash, array of byte "B", dhhash});
			enckeyc2s := sha1bufs(list of {keypack, dhhash, array of byte "C", dhhash});
			enckeys2c := sha1bufs(list of {keypack, dhhash, array of byte "D", dhhash});
			intkeyc2s := sha1bufs(list of {keypack, dhhash, array of byte "E", dhhash});
			intkeys2c := sha1bufs(list of {keypack, dhhash, array of byte "F", dhhash});

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
			(a, err) = parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				return (nil, "msg ignore: "+err);
			say("msg ignore, data: "+string getstr(a[0]));

			a = array[1] of ref Val;
			a[0] = ref Val.Str (array of byte "test!");
			err = writepacket(c, Sshlib->SSH_MSG_IGNORE, a);
			if(err != nil)
				return (nil, err);

			# xxx obviously wrong place, but openssh sshd won't send more after this (when compiled with debug mode)

			# byte      SSH_MSG_SERVICE_REQUEST
			# string    service name
			a = array[1] of ref Val;
			a[0] = ref Val.Str (array of byte "ssh-userauth");
			err = writepacket(c, Sshlib->SSH_MSG_SERVICE_REQUEST, a);
			if(err != nil)
				return (nil, err);

		Sshlib->SSH_MSG_SERVICE_ACCEPT =>
			cmd("### msg service accept");
			# byte      SSH_MSG_SERVICE_ACCEPT
			# string    service name
			(a, err) = parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				return (nil, err);
			say("service accepted: "+a[0].text());

			#byte      SSH_MSG_USERAUTH_REQUEST
			#string    user name
			#string    service name
			#string    "password"
			#boolean   FALSE
			#string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
			(user, pass) := fact->getuserpasswd(sprint("proto=pass server=%q service=ssh", addr));
			say("writing userauth request");
			vals := array[] of {
				ref Val.Str(array of byte user),
				ref Val.Str(array of byte "ssh-connection"),
				ref Val.Str(array of byte "password"),
				ref Val.Bool(0),
				ref Val.Str(array of byte pass),
			};
			err = writepacket(c, Sshlib->SSH_MSG_USERAUTH_REQUEST, vals);
			if(err != nil)
				return (nil, err);

		Sshlib->SSH_MSG_DEBUG =>
			cmd("### msg debug");
			# byte      SSH_MSG_DEBUG
			# boolean   always_display
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = parsepacket(d[1:], list of {Tbool, Tstr, Tstr});
			if(err != nil)
				return (nil, err);
			warn("remote debug: "+string getstr(a[1]));

		Sshlib->SSH_MSG_UNIMPLEMENTED =>
			cmd("### msg unimplemented");
			# byte      SSH_MSG_UNIMPLEMENTED
			# uint32    packet sequence number of rejected message
			(a, err) = parsepacket(d[1:], list of {Tint});
			if(err != nil)
				return (nil, err);
			pktno := getint(a[0]);
			say(sprint("packet %d is not implemented at remote...", pktno));

		Sshlib->SSH_MSG_USERAUTH_FAILURE =>
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

		Sshlib->SSH_MSG_USERAUTH_SUCCESS =>
			cmd("### msg userauth successful");
			# byte      SSH_MSG_USERAUTH_SUCCESS
			(a, err) = parsepacket(d[1:], nil);
			if(err != nil)
				return (nil, err);
			say("logged in!");
			return (c, nil);

		Sshlib->SSH_MSG_USERAUTH_BANNER =>
			cmd("### msg userauth banner");
			# byte      SSH_MSG_USERAUTH_BANNER
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			(a, err) = parsepacket(d[1:], list of {Tstr, Tstr});
			if(err != nil)
				return (nil, err);
			msg := string getstr(a[0]);
			warn("auth banner: "+msg);

		* =>
			cmd(sprint("### other packet type %d", int d[0]));
		}
	}
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

getrand(min, max: int): int
{
	# xxx
	return 1797;
	v := min+random->randomint(Random->ReallyRandom)%(max-min);
	if(v < 0)
		v = -v;
	return v;
}

cmd(s: string)
{
	say("\n"+s+"\n");
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

packpacket(c: ref Sshc, t: int, a: array of ref Val): array of byte
{
	bsize := 16;
	maclen := 0;
	k := c.tosrv;
	if(k != nil) {
		say("sending with encryption");
		bsize = k.bsize;
		maclen = 20; # xxx hardcode for now
	} else
		say("sending without encryption");

	size := 4+1;  # pktlen, padlen
	size += 1;  # type
	for(i := 0; i < len a; i++)
		size += a[i].size();
	say(sprint("packpacket, non-padded size %d", size));

	padlen := bsize - size % bsize;
	if(padlen < 4)
		padlen += bsize;
	size += padlen;
	say(sprint("packpacket, total buf %d, pktlen %d, padlen %d, maclen %d", size, size-4, padlen, maclen));

	d := array[size+maclen] of byte;

	o := 0;
	p32(d[o:], len d-maclen-4);  # length
	o += 4;
	d[o++] = byte padlen;  # pad length
	#if(padlen == 13)
	#	d[o-1] = byte (padlen+1);

	d[o++] = byte t;
	# will have to add data later
	for(i = 0; i < len a; i++) {
		inc := a[i].packbuf(d[o:]);
		if(a[i].size() != inc)
			raise "blah";
		say(sprint("elem, o %d, size %d, text %s", o, inc, a[i].text()));
		o += inc;
	}
	d[o:] = array[padlen] of {* => byte 1};  # xxx lousy padding
	o += padlen;
	say(sprint("o %d, len d %d", o, len d));
	if(o != len d-maclen)
		raise "error packing message";

	if(maclen > 0) {
		seqbuf := array[4] of byte;
		p32(seqbuf, c.outseq);
		say(sprint("mac, using seq %d, over %d", c.inseq, len d-maclen));
		say("rawbuf");
		hexdump(d[:len d-maclen]);

		state := kr->hmac_sha1(seqbuf, len seqbuf, k.intkey, nil, nil);
		kr->hmac_sha1(d[:len d-maclen], len d-maclen, k.intkey, d[len d-maclen:], state);
		say(sprint("calc digest %s", hex(d[len d-maclen:])));
	}
	if(k != nil)
		kr->aescbc(k.state, d, len d-maclen, kr->Encrypt);

	return d;
}

writepacket(c: ref Sshc, t: int, a: array of ref Val): string
{
	d := packpacket(c, t, a);
	return writebuf(c, d);
}

writebuf(c: ref Sshc, d: array of byte): string
{
	n := sys->write(c.fd, d, len d);
	if(n != len d)
		return sprint("write: %r");
	c.outseq++;
	return nil;
}

readpacket(c: ref Sshc): (array of byte, string)
{
	say("readpacket");

	bsize := 16;
	maclen := 0;
	k := c.fromsrv;
	if(k != nil) {
		say("receiving with encryption!");
		bsize = k.bsize;
		maclen = 20; # xxx hardcoded for now
	} else
		say("receiving without encryption");

	lead := array[bsize] of byte;
	n := c.b.read(lead, len lead);
	if(n < 0)
		return (nil, sprint("read packet length: %r"));
	if(n != len lead)
		return (nil, "short read for packet length");

	
	say("lead:");
	hexdump(lead);

	if(k != nil) {
		kr->aescbc(k.state, lead, len lead, kr->Decrypt);
		say("lead plain:");
		hexdump(lead);
	}

	# xxx in case of encryption, have to decrypt first.
	pktlen := g32(lead);
	padlen := int lead[4];
	paylen := pktlen-1-padlen;
	say(sprint("readpacket, pktlen %d, padlen %d, paylen %d, maclen %d", pktlen, padlen, paylen, maclen));
	if(pktlen == 0 && padlen == 0) {
		say("weird");
		for(;;) {
			ch := c.b.getb();
			if(ch == Bufio->EOF)
				warn("eof");
			else if(ch == Bufio->ERROR)
				warn("error");
			else {
				warn(sprint("char %x", int ch));
				continue;
			}
			return (nil, "weird");
		}
	}

	if((4+pktlen) % bsize != 0)
		return (nil, sprint("bad padding, length %d, blocksize %d, pad %d, mod %d", 4+pktlen, bsize, padlen, (4+pktlen) % bsize));

	if(paylen <= 0)
		return (nil, "bad paylen");
	#if(padlen <= 0)
	#	return (nil, "bad padlen");
	# xxx have to enforce min/max length of payload

	total := array[4+pktlen+maclen] of byte;
	total[:] = lead;
	rem := total[len lead:];

	n = c.b.read(rem, len rem);
	if(n < 0)
		return (nil, sprint("read payload: %r"));
	if(n != len rem)
		return (nil, "short read for payload");

	if(k != nil)
		kr->aescbc(k.state, rem, len rem-maclen, kr->Decrypt);

	say("################");
	if(dflag)
		sys->write(sys->fildes(2), total[5:len total-padlen], len total[5:len total-padlen]);
	say("################");

	# xxx later, will have to read mac & verify
	# mac = MAC(key, sequence_number || unencrypted_packet)
	if(maclen > 0) {
		seqbuf := array[4] of byte;
		p32(seqbuf, c.inseq);
		say(sprint("mac, using seq %d, over %d", c.inseq, len total-maclen));
		say("rawbuf");
		hexdump(total[:len total-maclen]);

		digest := array[kr->SHA1dlen] of byte;
		state := kr->hmac_sha1(seqbuf, len seqbuf, k.intkey, nil, nil);
		kr->hmac_sha1(total[:len total-maclen], len total-maclen, k.intkey, digest, state);
		ldig := hex(digest);
		pdig := hex(total[len total-maclen:]);
		say(sprint("calc digest %s", ldig));
		say(sprint("pkt digest %s", pdig));
		if(ldig != pdig)
			return (nil, sprint("bad signature, have %s, expected %s", pdig, ldig));
	}
	c.inseq++;

	return (total[5:len total-padlen-maclen], nil);
}

parsepacket(buf: array of byte, l: list of int): (array of ref Val, string)
{
	r: list of ref Val;
	o := 0;
	i := 0;
	for(; l != nil; l = tl l) {
		say(sprint("parse, %d elems left, %d bytes left", len l, len buf-o));
		case t := hd l {
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
				say(sprint("read mpint of length %d", length));
				if(length == 0) {
					r = ref Val.Mpint (IPint.strtoip("0", 10))::r;
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
					r = ref Val.Mpint (v)::r;
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

sha1bufs(l: list of array of byte): array of byte
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

hexfp(d: array of byte): string
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

mpintpack(v: ref IPint): array of byte
{
	return (ref Val.Mpint (v)).pack();
}

getint(v: ref Val): int
{
	pick vv := v {
	Int =>	return vv.v;
	}
	raise "not int";
}

getbyte(v: ref Val): byte
{
	pick vv := v {
	Byte =>	return byte vv.v;
	}
	raise "not byte";
}

getbig(v: ref Val): big
{
	pick vv := v {
	Big =>	return vv.v;
	}
	raise "not big";
}

getmpint(v: ref Val): ref IPint
{
	pick vv := v {
	Mpint =>	return vv.v;
	}
	raise "not mpint";
}

getstr(v: ref Val): array of byte
{
	pick vv := v {
	Str =>	return vv.buf;
	}
	raise "not str";
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


## Sshc

Sshc.login(fd: ref Sys->FD, addr: string): (ref Sshc, string)
{
	return login(fd, addr);
}

Sshc.text(s: self ref Sshc): string
{
	return "Sshc ()";
}


## misc

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

a2l[T](a: array of T): list of T
{
	l: list of T;
	for(i := len a-1; i >= 0; i--)
		l = a[i]::l;
	return l;
}


warn(s: string)
{
	sys->fprint(sys->fildes(2), "warn: %s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}
