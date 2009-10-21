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
	join, min, pid, killgrp, max, warn: import util;
include "../lib/sshlib.m";
	sshlib: Sshlib;
	Sshc, Cfg, Keys, Val: import sshlib;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshlib;
	getbool, getint, getipint, getstr, getbytes: import sshlib;
	valbyte, valbool, valint, valbig, valnames, valstr, valbytes, valmpint: import sshlib;

Ssh: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag,
tflag: int;
command:	string;
subsystem:	string;

packetc: chan of (array of byte, string, string, chan of int);
inc: chan of (array of byte, string);
readc:	chan of int;
outc:	chan of Out;
wrotec:	chan of int;
sshc: ref Sshc;

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
inwaiting:	int; # whether inreader is waiting for key exchange to be finished

Windowlow:	con 128*1024;
Windowhigh:	con 256*1024;
Minreadwin:	con 32*1024;  # only let inreader read when it can read Minreadwin

Maxkeypackets:	con big 2**31;
Maxkeybytes:	con big (1*1024*1024);

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
		'd' =>	sshlib->dflag = dflag++;
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

	packetc = chan of (array of byte, string, string, chan of int);
	readc = chan of int;
	inc = chan of (array of byte, string);
	outc = chan[1] of Out;
	wrotec = chan of int;

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	lerr: string;
	(sshc, lerr) = sshlib->handshake(conn.dfd, addr, cfg);
	if(lerr != nil)
		fail(lerr);
	say("hand shaked");

	lerr = sshlib->keyexchangestart(sshc);
	if(lerr != nil)
		fail("keyexchangestart: "+lerr);

	spawn packetreader();
	spawn inreader();
	spawn outwriter();

	vals: array of ref Val;
	for(;;) alt {
	(d, err) := <-inc =>
		if(err != nil)
			fail(err);

		if(sshc.kexbusy()) {
			readc <-= -1;
			inwaiting++;
			continue;
		}

		if(len d == 0) {
			if((subsystem == nil && command == nil) || tflag) {
				# send EOT
				vals = array[] of {valint(0), valbytes(array[] of {byte 4})};
				ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_DATA, vals);
				continue;
			} else {
				vals = array[] of {valint(0)};
				ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_EOF, vals);
				continue;
			}
		}
		vals = array[] of {
			valint(0),
			valbytes(d),
		};
		buf := sshlib->packpacket(sshc, Sshlib->SSH_MSG_CHANNEL_DATA, vals, random->randomint(Random->NotQuiteRandom)&16r7f);
		say(sprint("-> %s", sshlib->msgname(Sshlib->SSH_MSG_CHANNEL_DATA)));
		if(sys->write(sshc.fd, buf, len buf) != len buf)
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
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST, vals);
			windowfromrem += written;
			written = 0;
		}
		if(pendingfirst != nil) {
			outc <-= *pendingfirst.v;
			pendingfirst = pendingfirst.next;
			if(pendingfirst == nil)
				pendinglast = nil;
		}

	(d, ioerr, protoerr, rc) := <-packetc =>
		if(ioerr != nil)
			fail(ioerr);
		if(protoerr != nil) {
			sshlib->disconnect(sshc, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
			fail(protoerr);
		}

		dossh(d);
		say(sprint("nkeypkts %bd, nkeybytes %bd", sshc.nkeypkts, sshc.nkeybytes));
		if((sshc.nkeypkts >= Maxkeypackets || sshc.nkeybytes >= Maxkeybytes) && sshc.kexbusy()) {
			err := sshlib->keyexchangestart(sshc);
			if(err != nil)
				fail("keyexchangestart: "+err);
			say(sprint("key re-exchange started"));
		}
		rc <-= 0;
	}
}

dossh(d: array of byte)
{
	t := int d[0];

say(sprint("<- %s", sshlib->msgname(t)));

	case t {
	1 to 19 =>
		dotransport(d);

	20 to 29 or
	30 to 49 =>
		(newkeys, err) := sshlib->keyexchange(sshc, d);
		if(err != nil)
			fail(err);

		if(newkeys && sshc.needauth) {
			vals := array[] of {valstr("ssh-userauth")};
			ewritepacket(sshc, Sshlib->SSH_MSG_SERVICE_REQUEST, vals);  # remember we sent this, verify when response comes in
			sshc.needauth = 0;
		}

		if(newkeys && inwaiting) {
			readc <-= 0;
			inwaiting = 0;
		}

	50 to 59 or
	60 to 79 =>
		if(sshc.needauth) # xxx replace with a sshc.havekeys or something
			fail(sprint("remote sent auth messages before we requested them"));

		(authok, err) := sshlib->userauth(sshc, d);
		if(err != nil)
			fail(err);

		if(authok && sshc.needsession) {
			vals := array[] of {
				valstr("session"),
				valint(0),  # sender channel
				valint(Windowhigh),  # initial window size
				valint(32*1024),  # maximum packet size
			};
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_OPEN, vals);
			windowfromrem = Windowhigh;

			sshc.needsession = 0;
		}

	80 to 89 or
	90 to 127 =>
		if(sshc.needsession)
			fail(sprint("remote sent connection messages before we requested them"));

		doconnection(d);

	* =>
		sshlib->disconnect(sshc, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
		fail(sprint("other packet type %d, length body %d", t, len d));
	}
}


dotransport(d: array of byte)
{
	t := int d[0];
	d = d[1:];
	
	case t {
	Sshlib->SSH_MSG_DISCONNECT =>
		msg := eparsepacket(sshc, d, list of {Tint, Tstr, Tstr});
		code := getint(msg[0]);
		errmsg := getstr(msg[1]);
		lang := getstr(msg[2]);
		fail(sprint("disconnect from remote, code=%d, errmsg=%q, lang=%q", code, errmsg, lang));

	Sshlib->SSH_MSG_IGNORE =>
		msg := eparsepacket(sshc, d, list of {Tstr});
		say("msg ignore, data: "+getstr(msg[0]));

	Sshlib->SSH_MSG_UNIMPLEMENTED =>
		msg := eparsepacket(sshc, d, list of {Tint});
		pktno := getint(msg[0]);
		sshlib->disconnect(sshc, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
		fail(sprint("packet %d is not implemented at remote...", pktno));

	Sshlib->SSH_MSG_DEBUG =>
		msg := eparsepacket(sshc, d, list of {Tbool, Tstr, Tstr});
		display := getbool(msg[0]);
		text := getstr(msg[1]);
		lang := getstr(msg[2]);
		say(sprint("remote debug, display=%d, text=%q, lang=%q", display, text, lang));

	Sshlib->SSH_MSG_SERVICE_REQUEST =>
		fail(sprint("remote sent SSH_MSG_SERVICE_REQUEST, invalid"));

	Sshlib->SSH_MSG_SERVICE_ACCEPT =>

		# byte      SSH_MSG_SERVICE_ACCEPT
		# string    service name
		a := eparsepacket(sshc, d, list of {Tstr});
		say("service accepted: "+a[0].text());

		# xxx verify we requested it
		case getstr(a[0]) {
		"ssh-userauth" =>
			err := sshlib->userauthnext(sshc);
			if(err != nil)
				fail(err);

		* =>
			raise "other service accepted?";
		}

	* =>
		raise "other transport message"; # xxx
	}
}

doconnection(d: array of byte)
{
	t := int d[0];
	d = d[1:];
	vals: array of ref Val;
	case t {
	Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
		msg := eparsepacket(sshc, d, list of {Tint, Tint, Tint, Tint});
		lch := getint(msg[0]);
		rch := getint(msg[1]);
		winsize := getint(msg[2]);
		maxpktsize := getint(msg[3]);

		if(lch != 0)
			fail(sprint("remote claimed we requested channel %d", lch));

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
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote pty allocation request");

			vals = array[] of {
				valint(0),
				valstr("env"),
				valbool(0), # no reply please
				valstr("TERM"),
				valstr("vt100"),
			};
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
		}

		if(subsystem != nil) {
			omsg := array[] of {
				valint(0),
				valstr("subsystem"),
				valbool(1),  # want reply
				valstr(subsystem),
			};
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_REQUEST, omsg);
			say("wrote subsystem request");
		} else if(command != nil) {
			vals = array[] of {
				valint(0),   # recipient channel
				valstr("exec"),
				valbool(1),  # want reply
				valstr(command),
			};
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote request to execute command");
		} else {
			vals = array[] of {
				valint(0),   # recipient channel
				valstr("shell"),
				valbool(1),  # want reply
			};
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote request to start shell");
		}

		windowtorem = winsize;
		if(windowtorem >= Minreadwin)
			readc <-= windowtorem;

	Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
		msg := eparsepacket(sshc, d, list of {Tint});
		ch := getint(msg[0]);

	Sshlib->SSH_MSG_CHANNEL_FAILURE =>
		msg := eparsepacket(sshc, d, list of {Tint});
		ch := getint(msg[0]);
		fail("channel failure");

	Sshlib->SSH_MSG_CHANNEL_DATA =>
		msg := eparsepacket(sshc, d, list of {Tint, Tstr});
		ch := getint(msg[0]);
		buf := getbytes(msg[1]);

		writeout(0, buf);

	Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
		msg := eparsepacket(sshc, d, list of {Tint, Tint, Tstr});
		ch := getint(msg[0]);
		datatype := getint(msg[1]);
		buf := getbytes(msg[2]);
		if(datatype != Sshlib->SSH_EXTENDED_DATA_STDERR)
			warn("extended data but not stderr?");

		writeout(1, buf);

	Sshlib->SSH_MSG_CHANNEL_EOF =>
		msg := eparsepacket(sshc, d, list of {Tint});
		ch := getint(msg[0]);

	Sshlib->SSH_MSG_CHANNEL_CLOSE =>
		msg := eparsepacket(sshc, d, list of {Tint});
		ch := getint(msg[0]);
		say("channel closed");
		killgrp(pid());
		fail("remote closed connection");

	Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
		msg := eparsepacket(sshc, d, list of {Tint, Tint, Tstr, Tstr});
		ch := getint(msg[0]);
		code := getint(msg[1]);
		descr := getstr(msg[2]);
		lang := getstr(msg[3]);
		fail(sprint("channel open failure, channel=%d, code=%d, descr=%q, lang=%q", ch, code, descr, lang));

	Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
		msg := eparsepacket(sshc, d, list of {Tint, Tint});
		ch := getint(msg[0]);
		nbytes := getint(msg[1]);
		say(sprint("incoming window adjust for %d bytes", nbytes));

		doread := windowtorem <= 0;
		windowtorem += nbytes;
		if(doread && windowtorem >= Minreadwin)
			readc <-= windowtorem;

	Sshlib->SSH_MSG_CHANNEL_REQUEST =>
		msg := eparsepacket(sshc, d[:4+4], list of {Tint, Tint});
		strlen := getint(msg[1]);
		msg = eparsepacket(sshc, d[:4+4+strlen], list of {Tint, Tstr});
		which := getstr(msg[1]);
		case which {
		"signal" =>
			msg = eparsepacket(sshc, d, list of {Tint, Tstr, Tbool, Tstr});
			ch := getint(msg[0]);
			signame := getstr(msg[3]);
			# remote sending signal to us?

		"exit-status" =>
			msg = eparsepacket(sshc, d, list of {Tint, Tstr, Tbool, Tint});
			ch := getint(msg[0]);
			exitcode := getint(msg[3]);
			if(exitcode != 0)
				fail(sprint("exit code %d", exitcode));
			say(sprint("remote got exit-status %d", exitcode));
			killgrp(pid());
			exit;

		"exit-signal" =>
			msg = eparsepacket(sshc, d, list of {Tint, Tstr, Tbool, Tstr, Tbool, Tstr, Tstr});
			ch := getint(msg[0]);
			signame := getstr(msg[3]);
			# coredumped = getint(msg[4])
			errmsg := getstr(msg[5]);
			# lang = getstr(msg[6])
			if(errmsg == nil)
				errmsg = sprint("killed by signal %q", signame);
			say(sprint("remote got exit-signal %q, %q", signame, errmsg));
			fail(errmsg);

		* =>
			say(sprint("other channel request, ignoring: %q", which));
		}

	* =>
		raise "other connection message?"; # xxx
	}
}

writeout(toerr: int, buf: array of byte)
{
	if(windowfromrem-len buf < 0)
		fail(sprint("remote sent %d bytes while only %d allowed", len buf, windowfromrem));

	windowfromrem -= len buf;

	out := ref Out (toerr, buf);
	l := ref Link[ref Out](out, nil);
	if(pendinglast == nil) {
		pendingfirst = pendinglast = l;
	} else {
		pendinglast.next = l;
		pendinglast = l;
	}

	alt {
	outc <-= *pendingfirst.v =>
		pendingfirst = pendingfirst.next;
		if(pendingfirst == nil)
			pendinglast = nil;
	* =>
		;
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
	buf := array[Minreadwin] of byte;
	w := <-readc;
	for(;;) {
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

		for(;;) {
			inc <-= (d, nil);
			# -1 from readc means "try again on readc later".
			# 0 means "send data again",
			# >0 means "data was accepted" with number of bytes allowed to read
			while((w = <-readc) < 0)
				{}
			if(w > 0)
				break;
		}
	}
}

outwriter()
{
	fd1 := sys->fildes(1);
	fd2 := sys->fildes(2);
	for(;;) {
		o := <-outc;
		fd := fd1;
		if(o.toerr)
			fd = fd2;
		if(sys->write(fd, o.buf, len o.buf) != len o.buf)
			fail(sprint("write: %r"));
		wrotec <-= len o.buf;
	}
}

packetreader()
{
	rc := chan of int;  # synchronise with main, it may set new keys in sshc
	for(;;) {
		(d, ioerr, protoerr) := sshlib->readpacket(sshc);
		if(ioerr != nil)
			say("network error: "+ioerr);
		else if(protoerr != nil)
			say("protocol error: "+protoerr);
		else
			say(sprint("packet, payload length %d, type %d", len d, int d[0]));
		packetc <-= (d, ioerr, protoerr, rc);
		<-rc;
	}
}


eparsepacket(c: ref Sshc, d: array of byte, l: list of int): array of ref Val
{
	(a, err) := sshlib->parsepacket(d, l);
	if(err != nil) {
		sshlib->disconnect(sshc, Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
		fail(err);
	}
	return a;
}

ewritepacket(c: ref Sshc, t: int, vals: array of ref Val)
{
	err := sshlib->writepacket(sshc, t, vals);
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
