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
include "random.m";
	random: Random;
include "keyring.m";
	kr: Keyring;
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


warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}
