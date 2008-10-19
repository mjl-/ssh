implement Ssh;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "sshlib.m";
	sshlib: Sshlib;
	Sshc: import sshlib;

Ssh: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;

	arg->init(args);
	arg->setusage(arg->progname()+" [-d]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 0)
		arg->usage();


}

max(a, b: int): int
{
	if(a < b)
		return b;
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

fail(s: string)
{
	warn(s);
	raise "fail:"+s;
}
