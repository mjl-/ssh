implement Dsagen;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "keyring.m";
	kr: Keyring;

Dsagen: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	kr = load Keyring Keyring->PATH;

	arg->init(args);
	arg->setusage(arg->progname()+" [-d]");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 0)
		arg->usage();

	dsask := kr->genSK("dsa", "none", 2048); # xxx seems the length is not used!
	sys->print("%s\n", kr->sktostr(dsask));
}
