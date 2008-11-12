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
packetch: chan of (array of byte, string);
stdinch: chan of (array of byte, string);

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

	sys->pctl(Sys->NEWPGRP, nil);

	packetch = chan of (array of byte, string);
	stdinch = chan of (array of byte, string);

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	(c, lerr) := Sshc.login(conn.dfd, addr);
	if(lerr != nil)
		fail(lerr);
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
	ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, vals);

	spawn stdinreader();
	spawn packetreader(c);

	a: array of ref Val;
	for(;;) alt {
	(d, err) := <-stdinch =>
		if(err != nil)
			fail(err);
		if(len d == 0) {
			vals = array[1] of ref Val;
			vals[0] = ref Val.Int (0);
			ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_EOF, vals);
			continue;
		}
		vals = array[] of {
			ref Val.Int (0),
			ref Val.Str (d),
		};
		ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_DATA, vals);

	(d, err) := <-packetch =>
		if(err != nil)
			fail(err);

		case int d[0] {
		Sshlib->SSH_MSG_DISCONNECT =>
			cmd("### msg disconnect");
			discmsg := list of {Tint, Tstr, Tstr};
			a = eparsepacket(d[1:], discmsg);
			say("reason: "+a[0].text());
			say("descr: "+a[1].text());
			say("language: "+a[2].text());
			return;

		Sshlib->SSH_MSG_IGNORE =>
			cmd("### msg ignore");
			a = eparsepacket(d[1:], list of {Tstr});
			say("msg ignore, data: "+string getstr(a[0]));

			a = array[1] of ref Val;
			a[0] = ref Val.Str (array of byte "test!");
			ewritepacket(c, Sshlib->SSH_MSG_IGNORE, a);

		Sshlib->SSH_MSG_DEBUG =>
			cmd("### msg debug");
			# byte      SSH_MSG_DEBUG
			# boolean   always_display
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			a = eparsepacket(d[1:], list of {Tbool, Tstr, Tstr});
			say("remote debug: "+string getstr(a[1]));

		Sshlib->SSH_MSG_UNIMPLEMENTED =>
			cmd("### msg unimplemented");
			# byte      SSH_MSG_UNIMPLEMENTED
			# uint32    packet sequence number of rejected message
			a = eparsepacket(d[1:], list of {Tint});
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
			a = eparsepacket(d[1:], list of {Tint, Tint, Tint, Tint});

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
			ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote request to execute command");

		Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
			cmd("### channel success");
			eparsepacket(d[1:], list of {Tint});

		Sshlib->SSH_MSG_CHANNEL_FAILURE =>
			cmd("### channel failure");
			eparsepacket(d[1:], list of {Tint});

		Sshlib->SSH_MSG_CHANNEL_DATA =>
			cmd("### channel data");
			# byte      SSH_MSG_CHANNEL_DATA
			# uint32    recipient channel
			# string    data
			a = eparsepacket(d[1:], list of {Tint, Tstr});
			say("channel data:");
			buf := getstr(a[1]);
			if(sys->write(sys->fildes(1), buf, len buf) != len buf)
				fail(sprint("write: %r"));

		Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
			cmd("### channel extended data");
			# byte      SSH_MSG_CHANNEL_EXTENDED_DATA
			# uint32    recipient channel
			# uint32    data_type_code
			# string    data
			a = eparsepacket(d[1:], list of {Tint, Tint, Tstr});
			datatype := getint(a[1]);
			case datatype {
			Sshlib->SSH_EXTENDED_DATA_STDERR =>
				say("stderr data");
				buf := getstr(a[2]);
				if(sys->write(sys->fildes(2), buf, len buf) != len buf)
					fail(sprint("write: %r"));
			* =>
				warn("extended data but not stderr?");
				warn(string getstr(a[2]));
			}

		Sshlib->SSH_MSG_CHANNEL_EOF =>
			cmd("### channel eof");
			# byte      SSH_MSG_CHANNEL_EOF
			# uint32    recipient channel
			a = eparsepacket(d[1:], list of {Tint});
			say("channel done");

		Sshlib->SSH_MSG_CHANNEL_CLOSE =>
			cmd("### channel close");
			# byte      SSH_MSG_CHANNEL_CLOSE
			# uint32    recipient channel
			a = eparsepacket(d[1:], list of {Tint});
			say("channel closed");
			killgrp(sys->pctl(0, nil));
			return;

		Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
			cmd("### channel open failure");
			# byte      SSH_MSG_CHANNEL_OPEN_FAILURE
			# uint32    recipient channel
			# uint32    reason code
			# string    description in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			a = eparsepacket(d[1:], list of {Tint, Tint, Tstr, Tstr});
			fail("channel open failure: "+string getstr(a[2]));

		* =>
			cmd(sprint("### other packet type %d", int d[0]));
		}
	}
}

stdinreader()
{
	ccfd := sys->open("/dev/consctl", Sys->OWRITE);
	cfd := sys->open("/dev/cons", Sys->OREAD);
	if(ccfd == nil || sys->fprint(ccfd, "rawon") < 0 || cfd == nil) {
		stdinch <-= (nil, sprint("open console: %r"));
		return;
	}
	buf := array[32] of byte;
	for(;;) {
		n := sys->read(cfd, buf, len buf);
		if(n < 0) {
			say("stdin error");
			stdinch <-= (nil, sprint("read: %r"));
			return;
		}
		if(n == 0) {
			say("stdin eof");
			stdinch <-= (nil, nil);
			return;
		}
		d := array[n] of byte;
		d[:] = buf[:n];
		sys->write(sys->fildes(1), d, len d);
		stdinch <-= (d, nil);
	}
}

packetreader(c: ref Sshc)
{
	for(;;) {
		(d, perr) := sshlib->readpacket(c);
		if(perr != nil)
			say("net read error");
		else
			say(sprint("packet, payload length %d, type %d", len d, int d[0]));
		packetch <-= (d, perr);
	}
}


eparsepacket(d: array of byte, l: list of int): array of ref Val
{
	(a, err) := sshlib->parsepacket(d, l);
	if(err != nil)
		fail(err);
	return a;
}

ewritepacket(c: ref Sshc, t: int, vals: array of ref Val)
{
	err := sshlib->writepacket(c, t, vals);
	if(err != nil)
		fail(err);
}

cmd(s: string)
{
	say("\n"+s+"\n");
}

max(a, b: int): int
{
	if(a < b)
		return b;
	return a;
}

killgrp(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "killgrp");
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "ssh: %s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	warn(s);
	killgrp(sys->pctl(0, nil));
	raise "fail:"+s;
}
