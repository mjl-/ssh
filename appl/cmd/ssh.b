implement Ssh;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
include "dial.m";
	dial: Dial;
include "string.m";
	str: String;
include "keyring.m";
include "security.m";
	random: Random;
include "util0.m";
	util: Util0;
	l2a, readfile, join, min, pid, killgrp, max, warn: import util;
include "../lib/sshfmt.m";
	sshfmt: Sshfmt;
	Val: import sshfmt;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshfmt;
	valbyte, valbool, valint, valintb, valbig, valnames, valstr, valbytes, valmpint: import sshfmt;
include "../lib/sshlib.m";
	sshlib: Sshlib;
	Rssh, Tssh, Sshc, Cfg, Keys: import sshlib;

Ssh: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag,
sflag:	int;
term:	string;
command:	string;

packetc: chan of (ref Rssh, string, string, chan of int);
inc: chan of (array of byte, string);
readc:	chan of int;
outc:	chan of Out;
wrotec:	chan of (int, string);
termc:	chan of (string, string);
sshc: ref Sshc;

termfd: ref Sys->FD;

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
windowtorem:	big;
inwaiting:	int; # whether inreader is waiting for key exchange to be finished

Windowlow:	con big (128*1024);
Windowhigh:	con big (256*1024);
Minreadwin:	con 32*1024;  # only let inreader read when it can read Minreadwin
Maxpayloadsize:	con 32*1024;

Maxkeypackets:	con big 2**31;
Maxkeybytes:	con big (1*1024*1024);

localchannel := 1;
remotechannel := 2;
outmaxpayloadsize:	big;

Xfirstkex,
Xuserauthservice,
Xuserauthresult,
Xchannelopenresult,
Xptyresult,
Xcommandresult,
Xnormal: con iota;

expecting := Xfirstkex;

expectstrs := array[] of {
"firstkex", "userauthservice", "userauthresult", "channelopenresult", "ptyresult", "commandresult", "normal",
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	dial = load Dial Dial->PATH;
	str = load String String->PATH;
	random = load Random Random->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sshfmt = load Sshfmt Sshfmt->PATH;
	sshfmt->init();
	sshlib = load Sshlib Sshlib->PATH;
	sshlib->init();

	sys->pctl(Sys->NEWPGRP, nil);

	cfg := Cfg.default();
	arg->init(args);
	arg->setusage(arg->progname()+" [-d] [-t | -T term] [-A auth-methods] [-e enc-algs] [-m mac-algs] [-K kex-algs] [-H hostkey-algs] [-C compr-algs] [-k keyspec] [-s] [user@]addr [cmd]");
	while((cc := arg->opt()) != 0)
		case cc {
		'd' =>	sshlib->dflag = dflag++;
		'A' or 'e' or 'm' or 'K' or 'H' or 'C' or 'k' =>
			err := cfg.setopt(cc, arg->earg());
			if(err != nil)
				fail(err);
		's'=>	sflag++;
		't' =>	term = "ansi";
		'T' =>	term = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1 && len args != 2)
		arg->usage();
	(user, addr) := str->splitstrl(hd args, "@");
	if(addr == nil) {
		addr = user;
		user = "";
	} else
		addr = addr[1:];
	if(addr == nil)
		fail("empty address");
	addr = dial->netmkaddr(addr, nil, "ssh");
	
	if(len args == 2)
		command = hd tl args;
	else if(sflag)
		fail("-s requires command");

	packetc = chan of (ref Rssh, string, string, chan of int);
	readc = chan of int;
	inc = chan of (array of byte, string);
	outc = chan[1] of Out;
	wrotec = chan of (int, string);
	termc = chan of (string, string);

	conn := dial->dial(addr, nil);
	if(conn == nil)
		fail(sprint("dial %q: %r", addr));
	if(sys->fprint(conn.cfd, "keepalive") < 0)
		warn(sprint("setting keepalive: %r"));
	lerr: string;
	(sshc, lerr) = sshlib->handshake(conn.dfd, addr, cfg);
	if(lerr != nil)
		fail(lerr);
	say("handshake done");
	sshc.user = user;

	kextm := sshlib->keyexchangestart(sshc);
	ewritemsg(kextm);

	spawn packetreader();
	spawn inreader();
	spawn outwriter();

	vals: array of ref Val;
	for(;;) alt {
	(s, err) := <-termc =>
		if(err != nil) {
			warn("termctl: "+err);
			continue;
		}
		t := l2a(str->unquoted(s));
		if(t == nil)
			continue;
		case t[0] {
		"break" =>
			vals = array[] of {
				valint(remotechannel),
				valstr("break"),
				valbool(0),	# no reply
				valint(500),	# 500ms
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);

		"dimensions" =>
			if(len t != 3 || !isnum(t[1]) || !isnum(t[2]))
				continue;
			columns := int t[1];
			rows := int t[2];
			vals = array[] of {
				valint(remotechannel),
				valstr("window-change"),
				valbool(0),
				valint(columns),
				valint(rows),
				valint(0),
				valint(0),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);

		* =>
			say("termctl: bad command: "+s);
		}

	(d, err) := <-inc =>
		if(err != nil)
			disconnect(err);

		if(sshc.kexbusy()) {
			readc <-= -1;
			inwaiting++;
			continue;
		}

		if(len d == 0) {
			vals = array[] of {valint(remotechannel)};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_EOF, vals);
			continue;
		}
		vals = array[] of {
			valint(remotechannel),
			valbytes(d),
		};
		tm := ref Tssh (big 0, Sshlib->SSH_MSG_CHANNEL_DATA, vals, random->randomint(Random->NotQuiteRandom)&16r7f, nil);
		ewritemsg(tm);

		windowtorem -= big len d;
		if(windowtorem > big 0)
			readc <-= int bigmin(outmaxpayloadsize, windowtorem);

	(n, err) := <-wrotec =>
		if(err != nil)
			fail("local write: "+err);
		written += n;
		if(dflag) say(sprint("wrote %d, new written %d, current windowfromrem %bd", n, written, windowfromrem));
		if(windowfromrem <= Windowlow && windowfromrem+big written > Windowlow) {
			say("increasing window for remote");
			vals = array[] of {
				valint(remotechannel),
				valint(written),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST, vals);
			windowfromrem += big written;
			written = 0;
		}
		if(pendingfirst != nil) {
			outc <-= *pendingfirst.v;
			pendingfirst = pendingfirst.next;
			if(pendingfirst == nil)
				pendinglast = nil;
		}

	(m, ioerr, protoerr, rc) := <-packetc =>
		if(ioerr != nil)
			fail(ioerr);
		if(protoerr != nil)
			disconnect(protoerr);
		if(dflag) say("<- "+m.text());

		case m.t {
		1 to 19 or
		20 to 29 or
		30 to 49 =>
			transport(m);

		50 to 59 or
		60 to 79 =>
			expect(expecting==Xuserauthresult, "userauth layer message");
			userauth(m);

		80 to 89 or
		90 to 127 =>
			connection(m);

		* =>
			ewritepacket(Sshlib->SSH_MSG_UNIMPLEMENTED, array[] of {valintb(m.seq)});
			if(dflag) say("received packet we do not implement: "+m.text());
		}

		if(dflag) say(sprint("nkeypkts %bd, nkeybytes %bd", sshc.nkeypkts, sshc.nkeybytes));
		if((sshc.nkeypkts >= Maxkeypackets || sshc.nkeybytes >= Maxkeybytes) && sshc.kexbusy()) {
			kexmsg := sshlib->keyexchangestart(sshc);
			ewritemsg(kexmsg);
			say("key re-exchange started");
		}
		rc <-= 0;
	}
}

transport(m: ref Rssh)
{
	case m.t {
	Sshlib->SSH_MSG_DISCONNECT =>
		v := eparsepacket(m, list of {Tint, Tstr, Tstr});
		code := v[0].getint();
		errmsg := v[1].getstr();
		#lang := v[2].getstr();
		fail(sprint("remote disconnected: %s (%d)", errmsg, code));

	Sshlib->SSH_MSG_IGNORE =>
		v := eparsepacket(m, list of {Tstr});
		data := v[0].getstr();
		if(dflag) say("msg ignore, data: "+data);

	Sshlib->SSH_MSG_UNIMPLEMENTED =>
		v := eparsepacket(m, list of {Tint});
		pktno := v[0].getintb();
		disconnect(sprint("packetno %bd 'unimplemented' by remote", pktno));

	Sshlib->SSH_MSG_DEBUG =>
		v := eparsepacket(m, list of {Tbool, Tstr, Tstr});
		display := v[0].getbool();
		text := v[1].getstr();
		lang := v[2].getstr();
		if(dflag) say(sprint("remote debug, display=%d, text=%q, lang=%q", display, text, lang));

	Sshlib->SSH_MSG_SERVICE_REQUEST =>
		v := eparse(m.buf[1:], list of {Tstr});
		name := v[0].getstr();
		disconnect(sprint("remote sent 'service request' for %#q, invalid", name));

	Sshlib->SSH_MSG_SERVICE_ACCEPT =>
		v := eparsepacket(m, list of {Tstr});
		name := v[0].getstr();
		if(dflag) say("service accepted: "+name);

		case name {
		"ssh-userauth" =>
			expect(expecting==Xuserauthservice, "userauth service accept");

			(tm, err) := sshlib->userauthnext(sshc);
			if(err != nil)
				disconnect(err);
			if(tm != nil)
				ewritemsg(tm);
			expecting = Xuserauthresult;

		* =>
			disconnect(sprint("remote sent 'server accept' for unknown service %#q", name));
		}

	
	20 to 29 or
	30 to 49 =>
		(notimpl, newkeys, tms, err) := sshlib->keyexchange(sshc, m);
		if(err != nil)
			disconnect(err);
		if(notimpl) {
			ewritepacket(Sshlib->SSH_MSG_UNIMPLEMENTED, array[] of {valintb(m.seq)});
			if(dflag) say("received key exchange transport packet we do not implement: "+m.text());
			return;
		}

		for(; tms != nil; tms = tl tms)
			ewritemsg(hd tms);

		if(newkeys && expecting == Xfirstkex) {
			vals := array[] of {valstr("ssh-userauth")};
			ewritepacket(Sshlib->SSH_MSG_SERVICE_REQUEST, vals);  # remember we sent this, verify when response comes in
			expecting = Xuserauthservice;
		}

		if(newkeys && inwaiting) {
			readc <-= 0;
			inwaiting = 0;
		}

	* =>
		ewritepacket(Sshlib->SSH_MSG_UNIMPLEMENTED, array[] of {valintb(m.seq)});
		if(dflag) say("received transport packet we do not implement: "+m.text());
	}
}

userauth(m: ref Rssh)
{
	case m.t {
	Sshlib->SSH_MSG_USERAUTH_REQUEST =>
		disconnect("userauth request from server, invalid");

	Sshlib->SSH_MSG_USERAUTH_BANNER =>
		v := eparsepacket(m, list of {Tstr, Tstr});
		msg := v[0].getstr();
		lang := v[1].getstr();
		lang = nil;
		warn("auth banner: "+msg);

	Sshlib->SSH_MSG_USERAUTH_FAILURE or
	Sshlib->SSH_MSG_USERAUTH_SUCCESS =>
		expect(expecting==Xuserauthresult, "userauth result");

		(notimpl, authok, tm, err) := sshlib->userauth(sshc, m);
		if(err != nil)
			disconnect(err);
		if(notimpl) {
			ewritepacket(Sshlib->SSH_MSG_UNIMPLEMENTED, array[] of {valintb(m.seq)});
			if(dflag) say("received userauth packet we do not implement: "+m.text());
		}
		if(tm != nil)
			ewritemsg(tm);

		if(authok) {
			vals := array[] of {
				valstr("session"),
				valint(localchannel),
				valint(0),
				valint(Maxpayloadsize),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_OPEN, vals);

			expecting = Xchannelopenresult;
		}

	* =>
		ewritepacket(Sshlib->SSH_MSG_UNIMPLEMENTED, array[] of {valintb(m.seq)});
		if(dflag) say("received userauth packet we do not implement: "+m.text());
	}
}

connection(m: ref Rssh)
{
	if(expecting < Xchannelopenresult)
		disconnect(sprint("remote sent connection messages before we requested them"));

	case m.t {
	Sshlib->SSH_MSG_GLOBAL_REQUEST =>
		v := eparse(m.buf[1:], list of {Tstr, Tbool});
		name := v[0].getstr();
		wantreply := v[1].getbool();
		if(dflag) say(sprint("msg-global-request %#q, wantreply %d", name, wantreply));

		if(wantreply)
			ewritepacket(Sshlib->SSH_MSG_REQUEST_FAILURE, nil);

	Sshlib->SSH_MSG_REQUEST_SUCCESS =>
		# response to global request
		disconnect("remote sent unsolicited SSH_MSG_REQUEST_SUCCESS");

	Sshlib->SSH_MSG_REQUEST_FAILURE =>
		# response to global request
		disconnect("remote sent unsolicited SSH_MSG_REQUEST_FAILURE");


	Sshlib->SSH_MSG_CHANNEL_OPEN =>
		v := eparse(m.buf[1:], list of {Tstr, Tint, Tint, Tint});
		rch := v[1].getint();
		vals := array[] of {valint(rch), valint(Sshlib->SSH_OPEN_ADMINISTRATIVELY_PROHIBITED), valstr("no inboud channels"), valstr("")};
		ewritepacket(Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE, vals);

	Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
		v := eparsepacket(m, list of {Tint, Tint, Tint, Tint});
		lch := v[0].getint();
		rch := v[1].getint();
		winsize := v[2].getintb();
		maxpayloadsize := v[3].getintb(); # rfc naming is confusing, this is about data channel payload size, not (ssh) "packets"

		expect(expecting==Xchannelopenresult, "channel open confirmation");

		if(dflag) say(sprint("open confirmation, lch %d rch %d winsize %bd maxpayloadsize %bd", lch, rch, winsize, maxpayloadsize));
		if(lch != localchannel)
			disconnect(sprint("remote sent confirmation for unknown local channel %d (expected %d)", lch, localchannel));
		if(maxpayloadsize < big (32*1024))
			disconnect(sprint("remote sent max packet size that is too small, %bd, minimum is 32*1024", maxpayloadsize));
		outmaxpayloadsize = maxpayloadsize;
		remotechannel = rch;

		if(term != nil) {
			# see rfc4254, section 8 for more modes
			ONLCR: con byte 72;	# map NL to CR-NL
			termmode := array[] of {
				valbyte(ONLCR), valint(0),  # off
				valbyte(byte 0),
			};
			termmode = nil;
			vals := array[] of {
				valint(remotechannel),
				valstr("pty-req"),
				valbool(1),  # want reply
				valstr(term),
				valint(80), valint(24),  # dimensions chars
				valint(0), valint(0),  # dimensions pixels
				valbytes(sshfmt->pack(termmode, 0)),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote pty allocation request");

			expecting = Xptyresult;
		} else
			expecting = Xcommandresult;

		if(sflag) {
			vals := array[] of {
				valint(remotechannel),
				valstr("subsystem"),
				valbool(1),  # want reply
				valstr(command),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote subsystem request");
		} else if(command != nil) {
			vals := array[] of {
				valint(remotechannel),
				valstr("exec"),
				valbool(1),  # want reply
				valstr(command),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote request to execute command");
		} else {
			vals := array[] of {
				valint(remotechannel),
				valstr("shell"),
				valbool(1),  # want reply
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote request to start shell");
		}

		windowtorem = winsize;
		if(windowtorem >= big Minreadwin)
			readc <-= int bigmin(outmaxpayloadsize, windowtorem);

	Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
		v := eparsepacket(m, list of {Tint, Tint, Tstr, Tstr});
		ch := v[0].getint();
		code := v[1].getint();
		descr := v[2].getstr();
		lang := v[3].getstr();

		expect(expecting==Xchannelopenresult, "channel open failure");

		if(ch != localchannel)
			disconnect(sprint("channel open failure for unknown channel %d, expected %d", ch, localchannel));
		disconnect(sprint("channel open failed, code %d, descr %q, lang %q", code, descr, lang));

	Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
		v := eparsepacket(m, list of {Tint, Tint});
		ch := v[0].getint();
		nbytes := v[1].getint();
		if(dflag) say(sprint("incoming window adjust for %d bytes, for channel %d", nbytes, ch));

		expect(expecting>Xchannelopenresult, "channel window adjust");

		if(ch != localchannel)
			disconnect(sprint("received window adjust for unknown channel %d, expected %d", ch, localchannel));

		doread := windowtorem <= big 0;
		windowtorem += big nbytes;
		if(doread && windowtorem >= big Minreadwin)
			readc <-= int bigmin(outmaxpayloadsize, windowtorem);

	Sshlib->SSH_MSG_CHANNEL_DATA =>
		v := eparsepacket(m, list of {Tint, Tstr});
		ch := v[0].getint();
		buf := v[1].getbytes();
		if(len buf > Maxpayloadsize)
			disconnect(sprint("remote sent %d bytes channel payload, max is %d", len buf, Maxpayloadsize));

		expect(expecting>Xchannelopenresult, "channel data");

		if(ch != localchannel)
			disconnect(sprint("remote sent %d bytes for unknown channel %d", len buf, ch));

		writeout(0, buf);

	Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
		v := eparsepacket(m, list of {Tint, Tint, Tstr});
		ch := v[0].getint();
		datatype := v[1].getint();
		buf := v[2].getbytes();
		if(datatype != Sshlib->SSH_EXTENDED_DATA_STDERR)
			warn("extended data but not stderr");
		if(len buf > Maxpayloadsize)
			disconnect(sprint("remote sent %d bytes channel payload, max is %d", len buf, Maxpayloadsize));

		expect(expecting>Xchannelopenresult, "channel extended data");

		if(ch != localchannel)
			disconnect(sprint("remote sent %d bytes (extended data) for unknown channel %d", len buf, ch));

		writeout(1, buf);

	Sshlib->SSH_MSG_CHANNEL_EOF =>
		v := eparsepacket(m, list of {Tint});
		ch := v[0].getint();

		expect(expecting>Xchannelopenresult, "channel eof");
		if(ch != localchannel)
			disconnect(sprint("remote sent eof for unknown channel %d", ch));

	Sshlib->SSH_MSG_CHANNEL_CLOSE =>
		v := eparsepacket(m, list of {Tint});
		ch := v[0].getint();

		expect(expecting>Xchannelopenresult, "channel close");
		if(ch != localchannel)
			disconnect(sprint("remote sent close for unknown channel %d", ch));
		say("channel closed");
		killgrp(pid());
		# xxx send CLOSE too?
		disconnect("remote closed connection");

	Sshlib->SSH_MSG_CHANNEL_REQUEST =>
		v := eparse(m.buf[1:], list of {Tint, Tstr, Tbool});
		ch := v[0].getint();
		which := v[1].getstr();
		wantreply := v[2].getbool();

		expect(expecting>Xchannelopenresult, "channel request");

		if(ch != localchannel)
			disconnect(sprint("remote sent channel request %#q for unknown channel %d", which, ch));

		if(wantreply)
			case which {
			"signal" or
			"exit-status" or
			"exit-signal" =>
				disconnect(sprint("remote set 'wantreply' for channel request %#q, invalid", which));
			}
		case which {
		"signal" =>
			v = eparsepacket(m, list of {Tint, Tstr, Tbool, Tstr});
			signame := v[3].getstr();
			disconnect(sprint("remote sent us signal %#q, invalid", signame));

		"exit-status" =>
			v = eparsepacket(m, list of {Tint, Tstr, Tbool, Tint});
			exitcode := v[3].getint();
			if(exitcode != 0)
				disconnect(sprint("exit code %d", exitcode));
			say(sprint("remote got exit-status %d", exitcode));
			killgrp(pid());
			exit;

		"exit-signal" =>
			v = eparsepacket(m, list of {Tint, Tstr, Tbool, Tstr, Tbool, Tstr, Tstr});
			signame := v[3].getstr();
			coredumped := v[4].getint();
			errmsg := v[5].getstr();
			lang := v[6].getstr();
			if(dflag) say(sprint("remote exit due to signal %#q, coredumped %d, errmsg %#q, lang %#q", signame, coredumped, errmsg, lang));
			if(errmsg == nil)
				errmsg = "SIG"+signame;
			fail(errmsg);

		* =>
			if(dflag) say(sprint("other channel request, ignoring: %q", which));
			if(wantreply)
				ewritepacket(Sshlib->SSH_MSG_CHANNEL_FAILURE, array[] of {valint(remotechannel)});
		}

	Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
		v := eparsepacket(m, list of {Tint});
		ch := v[0].getint();

		if(expecting == Xptyresult) {
			expecting = Xcommandresult;
		} else if(expecting == Xcommandresult) {
			vals := array[] of {
				valint(remotechannel),
				valintb(Windowhigh),
			};
			ewritepacket(Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST, vals);
			windowfromrem = Windowhigh;
			expecting = Xnormal;

			if(term != nil) {
				termfd = sys->open("/dev/termctl", sys->OREAD);
				if(termfd == nil)
					say(sprint("open /dev/termctl: %r"));
				else
					spawn termreader();
			}
		} else
			disconnect(sprint("remote sent 'channel request success', expecting %#q", expectstrs[expecting]));

		if(ch != localchannel)
			disconnect(sprint("remote sent 'channel success' for unknown channel %d", ch));

	Sshlib->SSH_MSG_CHANNEL_FAILURE =>
		v := eparsepacket(m, list of {Tint});
		ch := v[0].getint();

		if(expecting == Xptyresult)
			expecting = Xcommandresult;
		else if(expecting == Xcommandresult) {
			expecting = Xnormal;
		} else
			disconnect(sprint("remote sent 'channel request failure', expecting %#q", expectstrs[expecting]));

		if(ch != localchannel)
			disconnect(sprint("remote sent 'channel failure' for unknown channel %d", ch));
		disconnect("channel request failed");

	* =>
		ewritepacket(Sshlib->SSH_MSG_UNIMPLEMENTED, array[] of {valintb(m.seq)});
		if(dflag) say("received connection packet we do not implement: "+m.text());
	}
}

writeout(toerr: int, buf: array of byte)
{
	if(windowfromrem-big len buf < big 0)
		fail(sprint("remote sent %d bytes while only %bd allowed", len buf, windowfromrem));

	windowfromrem -= big len buf;

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

termreader()
{
	buf := array[128] of byte;
	for(;;) {
		n := sys->read(termfd, buf, len buf);
		if(n < 0) {
			termc <-= (nil, sprint("read: %r"));
			return;
		}
		if(n == 0) {
			termc <-= (nil, "eof");
			return;
		}
		termc <-= (string buf[:n], nil);
	}
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
			inc <-= (nil, sprint("stdin read: %r"));
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
		if(n == 0) {
			inc <-= (nil, nil);
			return;
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
		{
			if(sys->write(fd, o.buf, len o.buf) != len o.buf) {
				wrotec <-= (0, sprint("%r"));
				return;
			}
		} exception x {
		"write on closed pipe" =>
			wrotec <-= (0, x);
			return;
		}
		wrotec <-= (len o.buf, nil);
	}
}

packetreader()
{
	rc := chan of int;  # synchronise with main, it may set new keys in sshc
	for(;;) {
		(m, ioerr, protoerr) := sshlib->readpacket(sshc);
		packetc <-= (m, ioerr, protoerr, rc);
		<-rc;
	}
}

eparse(buf: array of byte, l: list of int): array of ref Val
{
	(v, nil, err) := sshfmt->parse(buf, l);
	if(err != nil)
		disconnect("parsing packet");
	return v;
}

eparsepacket(m: ref Rssh, l: list of int): array of ref Val
{
	(v, err) := sshfmt->parseall(m.buf[1:], l);
	if(err != nil)
		disconnect("parsing packet");
	return v;
}

ewritepacket(t: int, vals: array of ref Val)
{
	m := ref Tssh (big 0, t, vals, 0, nil);
	ewritemsg(m);
}

ewritemsg(m: ref Tssh)
{
	if(dflag) say("-> "+m.text());
	buf := sshlib->packpacket(sshc, m);
	if(sys->write(sshc.fd, buf, len buf) != len buf)
		fail(sprint("ssh write: %r"));
}

expect(v: int, s: string)
{
	if(!v)
		disconnect(sprint("expected %#q, remote sent %#q", expectstrs[expecting], s));
}

disconnect(s: string)
{
	vals := array[] of {
		valint(Sshlib->SSH_DISCONNECT_PROTOCOL_ERROR),
		valstr("protocol error"),
		valstr(""),
	};
	tm := ref Tssh (big 0, Sshlib->SSH_MSG_DISCONNECT, vals, 0, nil);
	buf := sshlib->packpacket(sshc, tm);
	if(sys->write(sshc.fd, buf, len buf) != len buf)
		say(sprint("writing disconnect: %r"));
	fail("disconnected, "+s);
}

isnum(s: string): int
{
	return s != nil && str->drop(s, "0-9") == nil;
}

bigmin(a, b: big): big
{
	if(a < b)
		return a;
	return b;
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
