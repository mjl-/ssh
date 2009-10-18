implement Decenc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "encoding.m";
	encoding: Encoding;
include "util0.m";
	util: Util0;
	fail, readfd: import util;

Decenc: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	util = load Util0 Util0->PATH;
	util->init();

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

	buf := readfd(sys->fildes(0), -1);
	if(buf == nil)
		fail(sprint("read: %r"));
	if(dflag)
		buf = encoding->dec(string buf);
	else
		buf = array of byte encoding->enc(buf);
	n := sys->write(sys->fildes(1), buf, len buf);
	if(n != len buf)
		fail(sprint("write: %r"));
}
