implement Sshfmt;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "util0.m";
	util: Util0;
	prefix, suffix, rev, l2a, max, min, warn, join, eq, g32, g32i, g64, p32, p32i, p64: import util;
include "keyring.m";
	kr: Keyring;
	IPint: import kr;
include "sshfmt.m";


init()
{
	sys = load Sys Sys->PATH;
	kr = load Keyring Keyring->PATH;
	util = load Util0 Util0->PATH;
	util->init();
}

pack(v: array of ref Val, withlength: int): array of byte
{
	lensize := 0;
	if(withlength)
		lensize = 4;

	size := 0;
	for(i := 0; i < len v; i++)
		size += v[i].size();

	buf := array[lensize+size] of byte;
	if(withlength)
		p32i(buf, 0, size);

	o := lensize;
	for(i = 0; i < len v; i++)
		o += v[i].packbuf(buf[o:]);
	if(o != len buf)
		raise "packerror";
	return buf;
}

parseall(buf: array of byte, l: list of int): (array of ref Val, string)
{
	(v, o, err) := parse(buf, l);
	if(err != nil)
		return (nil, err);
	if(o != len buf)
		return (nil, sprint("leftover bytes, %d of %d used", o, len buf));
	return (v, nil);
}

parse(buf: array of byte, l: list of int): (array of ref Val, int, string)
{
	{
		(v, o) := xparse(buf, l);
		return (v, o, nil);
	} exception x {
	"parse:*" =>
		return (nil, 0, x[len "parse:":]);
	}
}

parseerror(s: string)
{
	raise "parse:"+s;
}

xparse(buf: array of byte, l: list of int): (array of ref Val, int)
{
	r: list of ref Val;
	o := 0;
	i := 0;
	for(; l != nil; l = tl l) {
		#say(sprint("parse, %d elems left, %d bytes left", len l, len buf-o));
		t := hd l;
		case t {
		Tbyte =>
			if(o+1 > len buf)
				parseerror("short buffer for byte");
			r = ref Val.Byte (buf[o++])::r;
		Tbool =>
			if(o+1 > len buf)
				parseerror("short buffer for byte");
			r = ref Val.Bool (int buf[o++])::r;
		Tint =>
			if(o+4 > len buf)
				parseerror("short buffer for int");
			e := ref Val.Int;
			(e.v, o) = g32(buf, o);
			r = e::r;
		Tbig =>
			if(o+8 > len buf)
				parseerror("short buffer for big");
			e := ref Val.Big;
			(e.v, o) = g64(buf, o);
			r = e::r;
		Tnames or
		Tstr or
		Tmpint =>
			if(o+4 > len buf)
				parseerror("short buffer for int for length");
			length: int;
			(length, o) = g32i(buf, o);
			if(o+length > len buf)
				parseerror("short buffer for name-list/string/mpint");
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
				parseerror(sprint("unknown type %d requested", t));
			if(o+t > len buf)
				parseerror("short buffer for byte-array");
			r = ref Val.Str (buf[o:o+t])::r;
			o += t;
		}
		#say(sprint("new val, size %d, text %s", (hd r).size(), (hd r).text()));
		i++;
	}
	return (l2a(rev(r)), o);
}


Val.getbyte(v: self ref Val): byte
{
	pick vv := v {
	Byte =>	return byte vv.v;
	}
	raise "not byte";
}

Val.getbool(v: self ref Val): int
{
	pick vv := v {
	Bool =>	return vv.v;
	}
	raise "not bool";
}

Val.getint(v: self ref Val): int
{
	pick vv := v {
	Int =>	return int vv.v;
	}
	raise "not int";
}

Val.getintb(v: self ref Val): big
{
	pick vv := v {
	Int =>	return vv.v;
	}
	raise "not int";
}

Val.getbig(v: self ref Val): big
{
	pick vv := v {
	Big =>	return vv.v;
	}
	raise "not big";
}

Val.getnames(v: self ref Val): list of string
{
	pick vv := v {
	Names =>	return vv.l;
	}
	raise "not names";
}

Val.getipint(v: self ref Val): ref IPint
{
	pick vv := v {
	Mpint =>	return vv.v;
	}
	raise "not mpint";
}

Val.getstr(v: self ref Val): string
{
	pick vv := v {
	Str =>	return string vv.buf;
	}
	raise "not string";
}

Val.getbytes(v: self ref Val): array of byte
{
	pick vv := v {
	Str =>	return vv.buf;
	}
	raise "not string (bytes)";
}


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
		p32i(d, 0, 0);
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
	p32i(d, 0, len buf);
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
		return p32(d, 0, v.v);
	Big =>
		return p64(d, 0, v.v);
	Names =>
		s := array of byte join(v.l, ",");
		p32i(d, 0, len s);
		d[4:] = s;
		return 4+len s;
	Str =>
		p32i(d, 0, len v.buf);
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
	return ref Val.Int (big v);
}
valintb(v: big): ref Val
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
