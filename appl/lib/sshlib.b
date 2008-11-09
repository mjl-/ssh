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
	IPint: import kr;
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

	sys->print("################\n");
	sys->write(sys->fildes(1), total[5:len total-padlen], len total[5:len total-padlen]);
	sys->print("################\n");

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



warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}
