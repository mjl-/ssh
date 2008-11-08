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

Val.pack(vv: self ref Val, d: array of byte): int
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

hex(d: array of byte): string
{
	if(len d == 0)
		return "";
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint(" %02x", int d[i]);
	return s[1:];
}

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

join(l: list of string, sep: string): string
{
	if(l == nil)
		return "";
	s := "";
	for(; l != nil; l = tl l)
		s += sep+hd l;
	return s[len sep:];
}

Sshc.text(s: self ref Sshc): string
{
	return "Sshc ()";
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
