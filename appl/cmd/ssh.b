implement Ssh;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
include "string.m";
	str: String;
include "keyring.m";
include "security.m";
	random: Random;
include "util0.m";
	util: Util0;
	min, pid, killgrp, max, warn: import util;
include "../lib/sshlib.m";
	sshlib: Sshlib;
	Sshc, Cfg, Keys, Val: import sshlib;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshlib;
	getbool, getint, getipint, getstr, getbytes: import sshlib;
	valbyte, valbool, valint, valbig, valnames, valstr, valbytes, valmpint: import sshlib;

Ssh: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag, tflag: int;
command:	string;
subsystem:	string;
packetc: chan of (array of byte, string, string);
inc: chan of (array of byte, string);
readc:	chan of int;
outc:	chan of (int, array of byte);
wrotec:	chan of int;

Link: adt[T] {
	v:	T;
	next:	cyclic ref Link;
};
Out: adt {
	toerr:	int;
	buf:	array of byte;
};
pendingfirst,
pendinglast:	ref Link[ref Out]; # buffers read from remote, not yet sent to outwriter.
written:	int; # bytes written to local stdout/stderr, but not yet used for increasing windowtorem
windowfromrem,
windowtorem:	int;

Windowlow:	con 128*1024;
Windowhigh:	con 256*1024;


init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	str = load String String->PATH;
	random = load Random Random->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sshlib = load Sshlib Sshlib->PATH;
	sshlib->init();

	sys->pctl(Sys->NEWPGRP, nil);

	cfg := Cfg.default();
	arg->init(args);
	arg->setusage(arg->progname()+" [-dt] [-A auth-methods] [-e enc-algs] [-m mac-algs] [-K kex-algs] [-H hostkey-algs] [-C compr-algs] [-k keyspec] [-s subsystem] addr [cmd]");
	while((cc := arg->opt()) != 0)
		case cc {
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		'A' or 'e' or 'm' or 'K' or 'H' or 'C' or 'k' =>
			err := cfg.setopt(cc, arg->earg());
			if(err != nil)
				fail(err);
		's'=>	subsystem = arg->earg();
		't' =>	tflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1 && len args != 2)
		arg->usage();
	addr := mkaddr(hd args);
	if(len args == 2)
		command = hd tl args;

	packetc = chan of (array of byte, string, string);
	readc = chan[1] of int;
	inc = chan of (array of byte, string);
	outc = chan[1] of (int, array of byte);
	wrotec = chan of int;

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
		valint(Windowhigh),  # initial window size
		valint(32*1024),  # maximum packet size
	};
	ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, vals);
	windowfromrem = Windowhigh;

	spawn packetreader(c);
	spawn inreader();
	spawn outwriter();

	for(;;) alt {
	(d, err) := <-inc =>
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

		windowtorem -= len d;
		if(windowtorem > 0)
			readc <-= windowtorem;

	n := <-wrotec =>
		written += n;
		say(sprint("wrote %d, new written %d, current windowfromrem %d", n, written, windowfromrem));
		if(windowfromrem <= Windowlow && windowfromrem+written > Windowlow) {
			say(sprint("increasing window for remote"));
			vals = array[] of {
				valint(0),
				valint(written),
			};
			ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST, vals);
			windowfromrem += written;
			written = 0;
		}
		if(pendingfirst != nil) {
			outc <-= *pendingfirst.v;
			pendingfirst = pendingfirst.next;
			if(pendingfirst == nil)
				pendinglast = nil;
		}

	(d, ioerr, protoerr) := <-packetc =>
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

		Sshlib->SSH_MSG_UNIMPLEMENTED =>
			msg := eparsepacket(c, d, list of {Tint});
			pktno := getint(msg[0]);
			sshlib->disconnect(c, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
			fail(sprint("packet %d is not implemented at remote...", pktno));

		Sshlib->SSH_MSG_DEBUG =>
			msg := eparsepacket(c, d, list of {Tbool, Tstr, Tstr});
			display := getbool(msg[0]);
			text := getstr(msg[1]);
			lang := getstr(msg[2]);
			say(sprint("remote debug, display=%d, text=%q, lang=%q", display, text, lang));

		Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
			msg := eparsepacket(c, d, list of {Tint, Tint, Tint, Tint});
			lch := getint(msg[0]);
			rch := getint(msg[1]);
			winsize := getint(msg[2]);
			maxpktsize := getint(msg[3]);

			say(sprint("open confirmation... lch %d rch %d", lch, rch));
			if((subsystem == nil && command == nil) || tflag) {
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

			if(subsystem != nil) {
				omsg := array[] of {
					valint(0),
					valstr("subsystem"),
					valbool(1),  # want reply
					valstr(subsystem),
				};
				ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, omsg);
				say("wrote subsystem request");
			} else if(command != nil) {
				vals = array[] of {
					valint(0),   # recipient channel
					valstr("exec"),
					valbool(1),  # want reply
					valstr(command),
				};
				ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
				say("wrote request to execute command");
			} else {
				vals = array[] of {
					valint(0),   # recipient channel
					valstr("shell"),
					valbool(1),  # want reply
				};
				ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
				say("wrote request to start shell");
			}

			windowtorem = winsize;
			if(windowtorem > 0)
				readc <-= windowtorem;

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

			writeout(0, buf);

		Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
			msg := eparsepacket(c, d, list of {Tint, Tint, Tstr});
			ch := getint(msg[0]);
			datatype := getint(msg[1]);
			buf := getbytes(msg[2]);
			if(datatype != Sshlib->SSH_EXTENDED_DATA_STDERR)
				warn("extended data but not stderr?");

			writeout(1, buf);

		Sshlib->SSH_MSG_CHANNEL_EOF =>
			msg := eparsepacket(c, d, list of {Tint});
			ch := getint(msg[0]);

		Sshlib->SSH_MSG_CHANNEL_CLOSE =>
			msg := eparsepacket(c, d, list of {Tint});
			ch := getint(msg[0]);
			say("channel closed");
			killgrp(pid());
			return;

		Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
			msg := eparsepacket(c, d, list of {Tint, Tint, Tstr, Tstr});
			ch := getint(msg[0]);
			code := getint(msg[1]);
			descr := getstr(msg[2]);
			lang := getstr(msg[3]);
			fail(sprint("channel open failure, channel=%d, code=%d, descr=%q, lang=%q", ch, code, descr, lang));

		Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
			msg := eparsepacket(c, d, list of {Tint, Tint});
			ch := getint(msg[0]);
			nbytes := getint(msg[1]);
			say(sprint("incoming window adjust for %d bytes", nbytes));

			doread := windowtorem <= 0;
			windowtorem += nbytes;
			if(doread && windowtorem > 0)
				readc <-= windowtorem;

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
				killgrp(pid());
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

writeout(toerr: int, buf: array of byte)
{
	if(windowfromrem-len buf < 0)
		fail(sprint("remote sent %d bytes while only %d allowed", len buf, windowfromrem));

	windowfromrem -= len buf;
	alt {
	outc <-= (0, buf) =>
		;
	* =>
		out := ref Out (toerr, buf);
		l := ref Link[ref Out](out, nil);
		if(pendinglast != nil)
			pendinglast.next = l;
		else
			pendingfirst = pendinglast = l;
	}
}

mkaddr(s: string): string
{
	if(str->splitstrl(s, "!").t1 == nil)
		s = sprint("net!%s!ssh", s);
	return s;
}

inreader()
{
	fd := sys->fildes(0);
	if((subsystem == nil && command == nil) || tflag) {
		cfd := sys->open("/dev/consctl", Sys->OWRITE);
		fd = sys->open("/dev/cons", Sys->OREAD);
		if(cfd == nil || sys->fprint(cfd, "rawon") < 0 || fd == nil) {
			inc <-= (nil, sprint("open console: %r"));
			return;
		}
	}
	buf := array[1024] of byte;
	for(;;) {
		w := <-readc;
		w = min(w, len buf);
		n := sys->read(fd, buf, w);
		if(n < 0) {
			say("stdin error");
			inc <-= (nil, sprint("read: %r"));
			return;
		}
		if(n == 0) {
			say("stdin eof");
			inc <-= (nil, nil);
			return;
		}
		d := array[n] of byte;
		d[:] = buf[:n];
		inc <-= (d, nil);
	}
}

outwriter()
{
	fd1 := sys->fildes(1);
	fd2 := sys->fildes(2);
	for(;;) {
		(toerr, buf) := <-outc;
		fd := fd1;
		if(toerr)
			fd = fd2;
		if(sys->write(fd, buf, len buf) != len buf)
			fail(sprint("write: %r"));
		wrotec <-= len buf;
	}
}

packetreader(c: ref Sshc)
{
	for(;;) {
		(d, ioerr, protoerr) := sshlib->readpacket(c);
		if(ioerr != nil)
			say("network error: "+ioerr);
		else if(protoerr != nil)
			say("protocol error: "+protoerr);
		else
			say(sprint("packet, payload length %d, type %d", len d, int d[0]));
		packetc <-= (d, ioerr, protoerr);
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

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	warn(s);
	killgrp(pid());
	raise "fail:"+s;
}
