implement Decenc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "encoding.m";
	encoding: Encoding;

Decenc: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] enc");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	modpath: string;
	case hd args {
	"base16" =>	modpath = Encoding->BASE16PATH;
	"base32" =>	modpath = Encoding->BASE32PATH;
	"base32a" =>	modpath = Encoding->BASE32APATH;
	"base64" =>	modpath = Encoding->BASE64PATH;
	* =>
		fail(sprint("bad encoding %q", hd args));
	}
	encoding = load Encoding modpath;

	buf := read();
	if(dflag)
		buf = encoding->dec(string buf);
	else
		buf = array of byte encoding->enc(buf);
	n := sys->write(sys->fildes(1), buf, len buf);
	if(n != len buf)
		fail(sprint("write: %r"));
}

read(): array of byte
{
	buf := array[0] of byte;
	fd := sys->fildes(0);
	for(;;) {
		d := array[Sys->ATOMICIO] of byte;
		n := sys->readn(fd, d, len d);
		if(n < 0)
			fail(sprint("read: %r"));
		if(n == 0)
			break;
		nbuf := array[len buf+n] of byte;
		nbuf[:] = buf;
		nbuf[len buf:] = d[:n];
		buf = nbuf;
	}
	return buf;
}

fail(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
	raise "fail:"+s;
}
