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
	arg->setusage(arg->progname()+" [-d] addr cmd");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 2)
		arg->usage();
	addr := hd args;
	command := hd tl args;

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	(c, err) := Sshc.login(conn.dfd, addr);
	if(err != nil)
		fail(err);
	say("logged in");

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

	a: array of ref Val;
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

		Sshlib->SSH_MSG_SERVICE_ACCEPT =>
			cmd("### msg service accept");
			# byte      SSH_MSG_SERVICE_ACCEPT
			# string    service name
			(a, err) = sshlib->parsepacket(d[1:], list of {Tstr});
			if(err != nil)
				fail(err);
			say("service accepted: "+a[0].text());
			# xxx what to do now?  or this is only used for auth?

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
			vals = array[] of {
				ref Val.Int (0),
				ref Val.Str (array of byte "exec"),
				ref Val.Bool (1),
				ref Val.Str (array of byte command),
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

		* =>
			cmd(sprint("### other packet type %d", int d[0]));
		}
	}
}

cmd(s: string)
{
	say("\n"+s+"\n");
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
