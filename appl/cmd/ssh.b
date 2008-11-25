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
include "../lib/sshlib.m";
	sshlib: Sshlib;
	Sshc, Cfg, Keys, Val: import sshlib;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshlib;
	getbool, getint, getipint, getstr, getbytes: import sshlib;
	valbyte, valbool, valint, valbig, valnames, valstr, valbytes, valmpint: import sshlib;
	hex, fingerprint, hexdump: import sshlib;

Ssh: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag, tflag: int;
packetch: chan of (array of byte, string, string);
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

	sys->pctl(Sys->NEWPGRP, nil);

	cfg := Cfg.default();
	arg->init(args);
	arg->setusage(arg->progname()+" [-dt] [-A auth-methods] [-e enc-algs] [-m mac-algs] [-K kex-algs] [-H hostkey-algs] [-C compr-algs] [-k keyspec] addr [cmd]");
	while((copt := arg->opt()) != 0) {
		case copt {
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		'A' or 'e' or 'm' or 'K' or 'H' or 'C' or 'k' =>
			err := cfg.setopt(copt, arg->earg());
			if(err != nil)
				fail(err);
		't' =>	tflag++;
		* =>	arg->usage();
		}
	}
	args = arg->argv();
	if(len args != 1 && len args != 2)
		arg->usage();
	addr := mkaddr(hd args);
	command: string;
	if(len args == 2)
		command = hd tl args;

	packetch = chan of (array of byte, string, string);
	stdinch = chan of (array of byte, string);

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	(c, lerr) := sshlib->login(conn.dfd, addr, cfg);
	if(lerr != nil)
		fail(lerr);
	say("logged in");

	vals := array[] of {
		valstr("session"),
		valint(0),  # sender channel
		valint(1*1024*1024),  # initial window size
		valint(32*1024),  # maximum packet size
	};
	ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, vals);

	spawn stdinreader();
	spawn packetreader(c);

	for(;;) alt {
	(d, err) := <-stdinch =>
		if(err != nil)
			fail(err);
		if(len d == 0) {
			vals = array[] of {valint(0)};
			ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_EOF, vals);
			continue;
		}
		vals = array[] of {
			valint(0),
			valbytes(d),
		};
		buf := sshlib->packpacket(c, Sshlib->SSH_MSG_CHANNEL_DATA, vals, random->randomint(Random->NotQuiteRandom)&16r7f);
		if(sys->write(c.fd, buf, len buf) != len buf)
			fail(sprint("write: %r"));

	(d, ioerr, protoerr) := <-packetch =>
		if(ioerr != nil)
			fail(ioerr);
		if(protoerr != nil) {
			sshlib->disconnect(c, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
			fail(protoerr);
		}

		t := int d[0];
		d = d[1:];
		case t {
		Sshlib->SSH_MSG_DISCONNECT =>
			msg := eparsepacket(c, d, list of {Tint, Tstr, Tstr});
			code := getint(msg[0]);
			errmsg := getstr(msg[1]);
			lang := getstr(msg[2]);
			say(sprint("disconnect from remote, code=%d, errmsg=%q, lang=%q", code, errmsg, lang));
			return;

		Sshlib->SSH_MSG_IGNORE =>
			msg := eparsepacket(c, d, list of {Tstr});
			say("msg ignore, data: "+getstr(msg[0]));

		Sshlib->SSH_MSG_DEBUG =>
			msg := eparsepacket(c, d, list of {Tbool, Tstr, Tstr});
			display := getbool(msg[0]);
			text := getstr(msg[1]);
			lang := getstr(msg[2]);
			say(sprint("remote debug, display=%d, text=%q, lang=%q", display, text, lang));

		Sshlib->SSH_MSG_UNIMPLEMENTED =>
			msg := eparsepacket(c, d, list of {Tint});
			pktno := getint(msg[0]);
			sshlib->disconnect(c, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
			fail(sprint("packet %d is not implemented at remote...", pktno));

		Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
			msg := eparsepacket(c, d, list of {Tint, Tint, Tint, Tint});
			lch := getint(msg[0]);
			rch := getint(msg[1]);
			winsize := getint(msg[2]);
			maxpktsize := getint(msg[3]);

			if(command == nil || tflag) {
				# see rfc4254, section 8 for more modes
				ONLCR: con byte 72;	# map NL to CR-NL
				termmode := array[] of {
					valbyte(ONLCR), valint(0),  # off
					valbyte(byte 0),
				};
				vals = array[] of {
					valint(0),
					valstr("pty-req"),
					valbool(1),  # want reply
					valstr("vt100"),
					valint(80), valint(24),  # dimensions chars
					valint(0), valint(0),  # dimensions pixels
					valbytes(sshlib->packvals(termmode, 0)),
				};
				ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
				say("wrote pty allocation request");
			}

			if(command == nil) {
				vals = array[] of {
					valint(0),   # recipient channel
					valstr("shell"),
					valbool(1),  # want reply
				};
				ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
				say("wrote request to start shell");
			} else {
				vals = array[] of {
					valint(0),   # recipient channel
					valstr("exec"),
					valbool(1),  # want reply
					valstr(command),
				};
				ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
				say("wrote request to execute command");
			}

		Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
			msg := eparsepacket(c, d, list of {Tint});
			ch := getint(msg[0]);

		Sshlib->SSH_MSG_CHANNEL_FAILURE =>
			msg := eparsepacket(c, d, list of {Tint});
			ch := getint(msg[0]);
			fail("channel failure");

		Sshlib->SSH_MSG_CHANNEL_DATA =>
			msg := eparsepacket(c, d, list of {Tint, Tstr});
			ch := getint(msg[0]);
			buf := getbytes(msg[1]);
			if(sys->write(sys->fildes(1), buf, len buf) != len buf)
				fail(sprint("write: %r"));

		Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
			msg := eparsepacket(c, d, list of {Tint, Tint, Tstr});
			ch := getint(msg[0]);
			datatype := getint(msg[1]);
			buf := getbytes(msg[2]);
			if(datatype != Sshlib->SSH_EXTENDED_DATA_STDERR)
				warn("extended data but not stderr?");

			if(sys->write(sys->fildes(2), buf, len buf) != len buf)
				fail(sprint("write: %r"));

		Sshlib->SSH_MSG_CHANNEL_EOF =>
			msg := eparsepacket(c, d, list of {Tint});
			ch := getint(msg[0]);

		Sshlib->SSH_MSG_CHANNEL_CLOSE =>
			msg := eparsepacket(c, d, list of {Tint});
			ch := getint(msg[0]);
			say("channel closed");
			killgrp(sys->pctl(0, nil));
			return;

		Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
			msg := eparsepacket(c, d, list of {Tint, Tint, Tstr, Tstr});
			ch := getint(msg[0]);
			code := getint(msg[1]);
			descr := getstr(msg[2]);
			lang := getstr(msg[3]);
			fail(sprint("channel open failure, channel=%d, code=%d, descr=%q, lang=%q", ch, code, descr, lang));

		Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
			# xxx use this
			msg := eparsepacket(c, d, list of {Tint, Tint});
			ch := getint(msg[0]);
			nbytes := getint(msg[1]);
			say(sprint("incoming window adjust for %d bytes", nbytes));

		Sshlib->SSH_MSG_CHANNEL_REQUEST =>
			msg := eparsepacket(c, d[:4+4], list of {Tint, Tint});
			strlen := getint(msg[1]);
			msg = eparsepacket(c, d[:4+4+strlen], list of {Tint, Tstr});
			which := getstr(msg[1]);
			case which {
			"signal" =>
				msg = eparsepacket(c, d, list of {Tint, Tstr, Tbool, Tstr});
				ch := getint(msg[0]);
				signame := getstr(msg[3]);
			"exit-status" =>
				msg = eparsepacket(c, d, list of {Tint, Tstr, Tbool, Tint});
				ch := getint(msg[0]);
				exitcode := getint(msg[3]);
				if(exitcode != 0)
					fail(sprint("exit code %d", exitcode));
				killgrp(sys->pctl(0, nil));
				return;

			"exit-signal" =>
				msg = eparsepacket(c, d, list of {Tint, Tstr, Tbool, Tstr, Tbool, Tstr, Tstr});
				ch := getint(msg[0]);
				signame := getstr(msg[3]);
				# coredumped = getint(msg[4])
				errmsg := getstr(msg[5]);
				# lang = getstr(msg[6])
				if(errmsg == nil)
					errmsg = sprint("killed by signal %q", signame);
				fail(errmsg);

			* =>
				say(sprint("other channel request, ignoring: %q", which));
			}

		* =>
			sshlib->disconnect(c, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
			fail(sprint("other packet type %d, length body %d", t, len d));
		}
	}
}

mkaddr(s: string): string
{
	if(str->splitstrl(s, "!").t1 == nil)
		s = sprint("net!%s!ssh", s);
	return s;
}

stdinreader()
{
	ccfd := sys->open("/dev/consctl", Sys->OWRITE);
	cfd := sys->open("/dev/cons", Sys->OREAD);
	if(ccfd == nil || sys->fprint(ccfd, "rawon") < 0 || cfd == nil) {
		stdinch <-= (nil, sprint("open console: %r"));
		return;
	}
	buf := array[1024] of byte;
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
		stdinch <-= (d, nil);
	}
}

packetreader(c: ref Sshc)
{
	for(;;) {
		(d, ioerr, protoerr) := sshlib->readpacket(c);
		if(ioerr != nil)
			say("network error: "+ioerr);
		if(protoerr != nil)
			say("protocol error: "+protoerr);
		else
			say(sprint("packet, payload length %d, type %d", len d, int d[0]));
		packetch <-= (d, ioerr, protoerr);
	}
}


eparsepacket(c: ref Sshc, d: array of byte, l: list of int): array of ref Val
{
	(a, err) := sshlib->parsepacket(d, l);
	if(err != nil) {
		sshlib->disconnect(c, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
		fail(err);
	}
	return a;
}

ewritepacket(c: ref Sshc, t: int, vals: array of ref Val)
{
	err := sshlib->writepacket(c, t, vals);
	if(err != nil)
		fail(err);
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
