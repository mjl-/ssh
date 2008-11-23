implement Sftpfs;

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
include "daytime.m";
	daytime: Daytime;
include "tables.m";
	tables: Tables;
	Table: import tables;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import styx;
include "../lib/sshlib.m";
	sshlib: Sshlib;
	Sshc, Cfg, Keys, Val: import sshlib;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshlib;
	getbyte, getint, getbig, getipint, getstr, getbytes: import sshlib;
	valbyte, valbool, valint, valbig, valnames, valmpint, valstr, valbytes: import sshlib;
	hex, fingerprint, hexdump: import sshlib;
include "sftp.m";

Sftpfs: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


Dflag, dflag: int;
time0: int;

Styxreadresp: type (list of array of byte, array of byte);
Sftpwritereq: type (array of byte, chan of (array of byte, array of byte, list of array of byte));
Insshpkt: type (array of byte, string, chan of list of array of byte);

insftpc: chan of (ref Rsftp, string);

Fid: adt {
	fid:	int;
	fh:	array of byte;  # file handle, nil == closed
	mode:	int;  # sftp mode flags.  only valid when fh != nil
	isdir:	int;
	path:	string;
	dirs:	list of ref Sys->Dir;
	attr:	ref Attr;

	text:	fn(f: self ref Fid): string;
};

# sftp op
Req: adt {
	seq:	int; # sftp sequence number
	m:	ref Tmsg; # styx tmsg
	canceled:	int;
	pick {
	Walk =>
		npath:	string;
		wm:	ref Tmsg.Walk;
	Open or Opendir =>
		fid, mode:	int;
	Stat =>		sm:	ref Tmsg.Stat;
	Read or
	Readdir =>	rm:	ref Tmsg.Read;
	Close =>	fid:	int;
	Ignore =>
	}
};

fids: ref Table[ref Fid];  # tmsg.fid
tabsftp: ref Table[ref Req];  # sftp seq
tabstyx: ref Table[ref Req];  # tmsg.tag
sftpgen := 1;
pathgen := 0;
sshc: ref Sshc;
nopens:	int;

Attr: adt {
	name:	string;
	flags:	int;
	size:	big;
	owner, group:	string;
	perms:	int;
	atime, mtime:	int;
	vals:	array of ref Val;

	mk:	fn(name: string, a: array of ref Val): ref Attr;
	isdir:	fn(a: self ref Attr): int;
	dir:	fn(a: self ref Attr, name: string): Sys->Dir;
	text:	fn(a: self ref Attr): string;
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	styx = load Styx Styx->PATH;
	styx->init();
	daytime = load Daytime Daytime->PATH;
	tables = load Tables Tables->PATH;
	sshlib = load Sshlib Sshlib->PATH;
	sshlib->init();

	sys->pctl(Sys->NEWPGRP, nil);

	cfg := Cfg.default();
	arg->init(args);
	arg->setusage(arg->progname()+" [-dD] [-A auth-methods] [-e enc-algs] [-m mac-algs] [-K kex-algs] [-H hostkey-algs] [-C compr-algs] [-k keyspec] addr");
	while((ch := arg->opt()) != 0)
		case ch {
		'D' =>	Dflag++;
		'd' =>	dflag++;
			sshlib->dflag = dflag-1;
		'e' or 'm' or 'K' or 'H' or 'C' or 'k' or 'A' =>
			err := cfg.setopt(ch, arg->earg());
			if(err != nil)
				fail(err);
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	addr := hd args;

	insshpktc := chan of Insshpkt;
	styxc := chan of (ref Tmsg, chan of Styxreadresp);
	sftpwritereqc := chan of Sftpwritereq;

	fids = fids.new(32, nil);
	tabsftp = tabsftp.new(32, nil);
	tabstyx = tabstyx.new(32, nil);

	addr = mkaddr(addr);
	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	(c, lerr) := sshlib->login(conn.dfd, addr, cfg);
	if(lerr != nil)
		fail(lerr);
	say("logged in");
	sshc = c;

	chanlocal = 3;
	msg := array[] of {
		valstr("session"),
		valint(chanlocal),	# channel
		valint(1*1024*1024),	# window size
		valint(32*1024),	# max packet size
	};
	ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, msg);

	time0 = daytime->now();

	spawn styxreader(sys->fildes(0), c.fd, styxc, sftpwritereqc);
	spawn sshreader(c, sys->fildes(0), insshpktc);
	spawn main(styxc, sys->fildes(0), c, sftpwritereqc, insshpktc);
}

mkaddr(s: string): string
{
	if(str->splitstrl(s, "!").t1 == nil)
		s = sprint("net!%s!ssh", s);
	return s;
}

sshreader(c: ref Sshc, styxfd: ref Sys->FD, insshpktc: chan of Insshpkt)
{
	respc := chan of list of array of byte;

	for(;;) {
		# read ssh packet & send it to main
		(d, perr) := sshlib->readpacket(c);
		if(perr != nil)
			say("ssh read error: "+perr);
		else
			say(sprint("sshreader: have packet, payload length %d, type %d", len d, int d[0]));
		insshpktc <-= (d, perr, respc);
		if(perr != nil)
			return;

		# receive styx responses to write from main
		styxbufs := <-respc;
		say(sprint("sshreader: received %d styxbufs from main", len styxbufs));
		for(l := styxbufs; l != nil; l = tl l) {
			buf := hd l;
			if(sys->write(styxfd, buf, len buf) != len buf)
				fail(sprint("write to styx: %r"));
		}
		styxbufs = nil;
	}
}

styxreader(styxfd, sshfd: ref Sys->FD, styxc: chan of (ref Tmsg, chan of (list of array of byte, array of byte)), sftpwritereqc: chan of Sftpwritereq)
{
	respc := chan of (list of array of byte, array of byte);
	writerespc := chan of (array of byte, array of byte, list of array of byte);

	for(;;) {
		# read styx message & pass it to main
		m := Tmsg.read(styxfd, 8*1024); # xxx
		if(m != nil && Dflag)
			warn("<- "+m.text());
		styxc <-= (m, respc);
		if(tagof m == tagof Tmsg.Readerror)
			return;

		# receive other packets & sftp data to write from main
		(pkts, sftpbuf) := <-respc;
		say(sprint("styxreader: main sent %d other packets, and %d bytes of sftpbuf", len pkts, len sftpbuf));
		err := writepkts(sshfd, pkts);
		if(err != nil)
			raise err; # xxx

		# keep asking main to turn our sftp buffer into ssh packets, taking window space into account
		while(len sftpbuf > 0) {
			sftpwritereqc <-= (sftpbuf, writerespc);
			pkt: array of byte;
			(pkt, sftpbuf, pkts) = <-writerespc;
			say(sprint("styxreader: main sent %d other packets, %d bytes of ssh pkt, and %d remaining sftpbuf bytes", len pkts, len pkt, len sftpbuf));
			err = writepkts(sshfd, pkts);
			if(err == nil && pkt != nil)
				err = writepkts(sshfd, pkt::nil);
			if(err != nil)
				raise err; # xxx
		}

		# let main know we are done writing
		say("styxreader: done writing for styx message");
		sftpwritereqc <-= (nil, nil);
	}
}

writepkts(fd: ref Sys->FD, l: list of array of byte): string
{
	for(; l != nil; l = tl l) {
		d := hd l;
		if(sys->write(fd, d, len d) != len d)
			return sprint("write to remote ssh: %r");
	}
	return nil;
}


Windowinlow: con 256*1024;
Windowinunit: con 512*1024;

chanlocal: int;
chanremote: int;
windowin := 1*1024*1024;	# how many bytes can come in
windowout := 0;	# how many bytes can go out

main(styxc: chan of (ref Tmsg, chan of Styxreadresp), styxfd: ref Sys->FD, c: ref Sshc, realsftpwritereqc: chan of Sftpwritereq, insshpktc: chan of Insshpkt)
{
	# state, managed by main and its helper function dossh()
	writingssh := 0;
	writingstyx := 0;
	outsshpkts: list of array of byte;  # kept in reverse order
	outstyxpkts: list of array of byte;  # kept in reverse order

	bogussftpwritereqc := chan of Sftpwritereq;
	sftpwritereqc := realsftpwritereqc;

done:
	for(;;) {
		sftpwritereqc = realsftpwritereqc;
		if(!writingssh || windowout == 0)
			sftpwritereqc = bogussftpwritereqc;

		say(sprint("main: nopens %d, windowin %d, windowout %d, chanlocal %d, chanremote %d, sftpgen %d, pathgen %d", nopens, windowin, windowout, chanlocal, chanremote, sftpgen, pathgen));

		alt {
		(gm, respch) := <-styxc =>
			if(gm == nil)
				break done;
			pick m := gm {
			Readerror =>
				warn("read error: "+m.error);
				break done;
			}

			(styxbuf, sftpbuf) := dostyx(gm);
			say(sprint("main: dostyx returned %d bytes of sftpbuf, and %d bytes of styxbuf", len sftpbuf, len styxbuf));
			respch <-= (lists->reverse(outsshpkts), sftpbuf);
			outsshpkts = nil;
			writingssh = 1;

			if(styxbuf != nil)
				outstyxpkts = styxbuf::outstyxpkts;
			if(!writingstyx && outstyxpkts != nil) {
				writepkts(styxfd, lists->reverse(outstyxpkts));
				outstyxpkts = nil;
			}

		(buf, respc) := <-sftpwritereqc =>
			if(respc == nil) {
				# xxx start writing pending ssh msgs immediately?  or let styxreader do it after all?
				writingssh = 0;
				continue;
			}
			say(sprint("main: request for writing %d bytes of sftp buf", len buf));

			if(outsshpkts != nil) {
				say(sprint("main: first making styxread write other ssh packets"));
				respc <-= (nil, buf, lists->reverse(outsshpkts));
				outsshpkts = nil;
				continue;
			}
			n := len buf;
			n = min(n, windowout);
			windowout -= n;
			omsg := array[] of {valint(chanremote), valbytes(buf[:n])};
			outbuf := sshlib->packpacket(c, Sshlib->SSH_MSG_CHANNEL_DATA, omsg, 0);
			respc <-= (outbuf, buf[n:], lists->reverse(outsshpkts));
			outsshpkts = nil;

		(d, err, respc) := <-insshpktc =>
			if(err != nil)
				fail(err);

			if(respc == nil) {
				# xxx start writing pending styx msgs immediately?  or let the sshreader do it after all?
				writingstyx = 0;
				continue;
			}

			(sshpkt, styxbufs, sftpbufs) := dossh(c, d);
			say(sprint("main: dossh returned sshpkt len %d, %d styxbufs, and %d sftpbufs", len sshpkt, len styxbufs, len sftpbufs));
			respc <-= styxbufs;

			# xxx this can be done in dossh()?
			for(l := sftpbufs; l != nil; l = tl l) {
				omsg := array[] of {valint(chanremote), valbytes(hd l)};
				outpkt := sshlib->packpacket(c, Sshlib->SSH_MSG_CHANNEL_DATA, omsg, 0);
				outsshpkts = outpkt::outsshpkts;
			}
			outsshpkts = lists->reverse(outsshpkts);
			if(sshpkt != nil)
				outsshpkts = sshpkt::outsshpkts;

			if(!writingssh && outsshpkts != nil) {
				say(sprint("main: writing %d outsshpkts ourselves", len outsshpkts));
				writepkts(c.fd, outsshpkts);
				outsshpkts = nil;
			}
		}
	}
	killgrp(sys->pctl(0, nil));
}

insshdata: array of byte;
dossh(c: ref Sshc, d: array of byte): (array of byte, list of array of byte, list of array of byte)
{
	t := int d[0];
	d = d[1:];
	case t {
	Sshlib->SSH_MSG_DISCONNECT =>
		discmsg := list of {Tint, Tstr, Tstr};
		msg := eparsepacket(d, discmsg);
		say(sprint("ssh disconnect, reason=%q descr=%q lang=%q", msg[0].text(), msg[1].text(), msg[2].text()));

	Sshlib->SSH_MSG_IGNORE =>
		eparsepacket(d, list of {Tstr});

	Sshlib->SSH_MSG_DEBUG =>
		msg := eparsepacket(d, list of {Tbool, Tstr, Tstr});
		say("ssh debug, text: "+getstr(msg[1]));

	Sshlib->SSH_MSG_UNIMPLEMENTED =>
		msg := eparsepacket(d, list of {Tint});
		pktno := getint(msg[0]);
		fail(sprint("packet %d is not implemented at remote...", pktno));

	Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
		msg := eparsepacket(d, list of {Tint, Tint, Tint, Tint});
		ch := getint(msg[0]);
		chanremote = getint(msg[1]);
		windowout = getint(msg[2]);
		maxpktsize := getint(msg[3]);
		if(ch != chanlocal)
			fail(sprint("remote sent data for unknown local channel %d", ch));
		say(sprint("initial outgoing windowsize is %d", windowout));
		# xxx should keep track of max packet size

		omsg := array[] of {
			valint(chanremote),
			valstr("subsystem"),
			valbool(1),  # want reply
			valstr("sftp"),
		};
		ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, omsg);
		say("wrote sftp subsystem request");

	Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
		msg := eparsepacket(d, list of {Tint});
		ch := getint(msg[0]);
		if(ch != chanlocal)
			fail(sprint("'channel success' for unknown channel %d", ch));

		sftpmsg := array[] of {valbyte(byte SSH_FXP_INIT), valint(3)};
		omsg := array[] of {valint(chanremote), valbytes(sshlib->packvals(sftpmsg, 1))};
		ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_DATA, omsg);
		say("wrote sftp init command");

	Sshlib->SSH_MSG_CHANNEL_FAILURE =>
		msg := eparsepacket(d, list of {Tint});
		ch := getint(msg[0]);
		if(ch != chanlocal)
			fail(sprint("'channel failure' for unknown channel %d", ch));
		fail("channel failure");

	Sshlib->SSH_MSG_CHANNEL_DATA =>
		say("ssh 'channel data'");
		msg := eparsepacket(d, list of {Tint, Tstr});
		ch := getint(msg[0]);
		if(ch != chanlocal)
			fail(sprint("remote sent data for unknown channel %d", ch));

		buf := getbytes(msg[1]);
		windowin -= len buf;
		if(windowin < 0)
			fail("remote is writing beyond window size?");
		sshpkt: array of byte;
		if(windowin < Windowinlow) {
			windowin += Windowinunit;
			omsg := array[] of {valint(chanremote), valint(Windowinunit)};
			sshpkt = sshlib->packpacket(c, Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST, omsg, 0);
		}

		# handle all completely read sftp packets
		styxmsgs: list of array of byte;
		sftpmsgs: list of array of byte;
		insshdata = add(insshdata, buf);
		while(len insshdata >= 4) {
			length := g32(insshdata);
			# xxx should check for max packet length
			if(len insshdata < 4+length)
				break;

			(rsftp, err) := rsftpparse(insshdata[:4+length]);
			if(err != nil)
				fail("parsing rsftp: "+err);
			insshdata = insshdata[4+length:];
			(styxmsg, sftpbuf) := dosftp(rsftp);
			if(styxmsg != nil)
				styxmsgs = styxmsg::styxmsgs;
			if(sftpbuf != nil)
				sftpmsgs = sftpbuf::sftpmsgs;
		}
		
		return (sshpkt, lists->reverse(styxmsgs), lists->reverse(sftpmsgs));

	Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
		say("ssh 'channel extended data'");
		msg := eparsepacket(d, list of {Tint, Tint, Tstr});
		ch := getint(msg[0]);
		datatype := getint(msg[1]);
		data := getbytes(msg[2]);

		if(ch != chanlocal)
			fail(sprint("remote sent extended data for unknown channel %d", ch));
		windowin -= len data;
		# xxx should send window adjust here too

		if(datatype != Sshlib->SSH_EXTENDED_DATA_STDERR)
			warn("received extended data other than stderr");
		if(sys->write(sys->fildes(2), data, len data) != len data)
			fail(sprint("write: %r"));

	Sshlib->SSH_MSG_CHANNEL_EOF =>
		msg := eparsepacket(d, list of {Tint});
		ch := getint(msg[0]);
		if(ch != chanlocal)
			fail(sprint("remote sent channel eof for unknown channel %d", ch));
		# xxx if sftp data pending (which won't be a full message, warn)

	Sshlib->SSH_MSG_CHANNEL_CLOSE =>
		msg := eparsepacket(d, list of {Tint});
		ch := getint(msg[0]);
		if(ch != chanlocal)
			fail(sprint("remote sent channel close for unknown channel %d", ch));
		# xxx if sftp data pending (which won't be a full message, warn)

	Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
		msg := eparsepacket(d, list of {Tint, Tint, Tstr, Tstr});
		ch := getint(msg[0]);
		reason := getstr(msg[2]);
		if(ch != chanlocal)
			fail(sprint("'channel open failure' for unknown channel %d", ch));
		fail("channel open failure: "+reason);

	Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
		msg := eparsepacket(d, list of {Tint, Tint});
		ch := getint(msg[0]);
		nbytes := getint(msg[1]);
		if(ch != chanlocal)
			fail(sprint("'channel window adjust' for unknown channel %d", ch));
		windowout += nbytes;
		say(sprint("incoming window adjust for %d bytes", nbytes));
	* =>
		fail(sprint("ssh, other packet type %d, len data %d", int t, len d));
	}
	return (nil, nil, nil);
}

ewritepacket(c: ref Sshc, t: int, msg: array of ref Val)
{
	err := sshlib->writepacket(c, t, msg);
	if(err != nil)
		fail(err);
}

eparsepacket(d: array of byte, l: list of int): array of ref Val
{
	(a, err) := sshlib->parsepacket(d, l);
	if(err != nil)
		fail(err);
	return a;
}


Fid.text(f: self ref Fid): string
{
	return sprint("Fid (fid %d, fh %d, mode %o, isdir %d, path %q, len dirs %d, attr %s)", f.fid, f.fh != nil, f.mode, f.isdir, f.path, len f.dirs, f.attr.text());
}

Attr.isdir(a: self ref Attr): int
{
	return a.perms&8r0040000;
}

Attr.dir(a: self ref Attr, name: string): Sys->Dir
{
	d := sys->zerodir;
	d.name = name;
	if(name == nil)
		d.name = a.name;
	d.uid = a.owner;
	d.gid = a.group;
	d.muid = "none";
	d.qid = Sys->Qid (big pathgen++, 0, Sys->QTFILE);
	d.mode = a.perms&8r777;
	if(a.isdir()) {
		d.qid.qtype = Sys->QTDIR;
		d.mode |= Sys->DMDIR;
	}
	d.atime = a.atime;
	d.mtime = a.mtime;
	d.length = a.size;
	return d;
}

Attr.mk(name: string, a: array of ref Val): ref Attr
{
	flags := getint(a[0]);
	size := getbig(a[1]);
	uid := string getint(a[2]);
	gid := string getint(a[3]);
	perms := getint(a[4]);
	atime := getint(a[5]);
	mtime := getint(a[6]);
	attr := ref Attr (name, flags, size, uid, gid, perms, atime, mtime, a);
	return attr;
}

Attr.text(a: self ref Attr): string
{
	return sprint("Attr (name %q, size %bd, uid/gid %q %q mode %o isdir %d atime %d mtime %d", a.name, a.size, a.owner, a.group, a.perms&8r777, a.isdir(), a.atime, a.mtime);
}


Rsftp: adt {
	id:	int;  # bogus for Version
	pick {
	Version =>	version:	int;
	Status =>
		status:	int;
		errmsg, lang:	string;
	Handle =>	fh:	array of byte;
	Data =>		buf:	array of byte;
	Name =>		attrs:	array of ref Attr;
	Attrs =>	attr:	ref Attr;
	}

	text:	fn(m: self ref Rsftp): string;
};


rsftpparse(buf: array of byte): (ref Rsftp, string)
{
	msg := eparsepacket(buf[:4+1], list of {Tint, Tbyte});

	length := getint(msg[0]);
	if(length > 32*1024) # xxx
		return (nil, "packet too large");
	t := int getbyte(msg[1]);
	say(sprint("sftp msg, length %d, t %d", length, t));

	# fields in attrs
	lattrs := list of {Tint, Tbig, Tint, Tint, Tint, Tint, Tint};

	m: ref Rsftp;
	buf = buf[4+1:];
	case t {
	SSH_FXP_VERSION =>
		# xxx can there be extensions, should parse those too.
		msg = eparsepacket(buf[:4], list of {Tint});
		# xxx read the extensions too!
		m = ref Rsftp.Version (0, getint(msg[0]));

	SSH_FXP_STATUS =>
		msg = eparsepacket(buf, list of {Tint, Tint, Tstr, Tstr});
		m = ref Rsftp.Status (getint(msg[0]), getint(msg[1]), getstr(msg[2]), getstr(msg[3]));
		# if(status < 0 || status > xxx)
		# 	return (nil, sprint("unknown status type %d", t));

	SSH_FXP_HANDLE =>
		msg = eparsepacket(buf, list of {Tint, Tstr});
		m = ref Rsftp.Handle (getint(msg[0]), getbytes(msg[1]));

	SSH_FXP_DATA =>
		msg = eparsepacket(buf, list of {Tint, Tstr});
		m = ref Rsftp.Data (getint(msg[0]), getbytes(msg[1]));

	SSH_FXP_NAME =>
		msg = eparsepacket(buf[:8], list of {Tint, Tint});
		id := getint(msg[0]);
		nattr := getint(msg[1]);
		say(sprint("names has %d entries", nattr));
		buf = buf[8:];

		multiattrs: list of int;
		for(i := 0; i < nattr; i++)
			multiattrs = Tstr::Tstr::Tint::Tbig::Tint::Tint::Tint::Tint::Tint::multiattrs;
		stat := eparsepacket(buf, multiattrs);
		for(i = 0; i < len stat; i++)
			say(sprint("stat[%d] = %s", i, stat[i].text()));
		o := 0;
		i = 0;
		attrs := array[nattr] of ref Attr;
		while(o < len stat) {
			say(sprint("stat, o %d, total %d", o, len stat));
			filename := getstr(stat[o]);
			attr := Attr.mk(getstr(stat[o]), stat[o+2:o+2+len lattrs]);
			say(sprint("have attr, filename %s, attr %s", filename, attr.text()));
			attrs[i++] = attr;
			o += 2+len lattrs;
		}
		m = ref Rsftp.Name (id, attrs);

	SSH_FXP_ATTRS =>
		msg = eparsepacket(buf, Tint::lattrs);
		id := getint(msg[0]);
		attr := Attr.mk(nil, msg[1:]);
		m = ref Rsftp.Attrs (id, attr);

	SSH_FXP_EXTENDED or SSH_FXP_EXTENDED_REPLY =>
		return (nil, "extended (reply) not supported");
	* =>
		return (nil, sprint("unknown reply, type %d", t));
	}
	return (m, nil);
}

rsftptagnames := array[] of {
	"Version", "Status", "Handle", "Data", "Name", "Attrs",
};
Rsftp.text(mm: self ref Rsftp): string
{
	s := sprint("Rsftp.%s (", rsftptagnames[tagof mm]);
	pick m := mm {
	Version =>	s += sprint("version %d", m.version);
	Status =>	s += sprint("status %d, errmsg %q, lang %q", m.status, m.errmsg, m.lang);
	Handle =>	s += "handle "+hex(m.fh);
	Data =>		s += sprint("len data %d", len m.buf);
	Name =>		s += sprint("len attrs %d", len m.attrs);
	Attrs =>	s += "attr "+m.attr.text();
	}
	s += ")";
	return s;
}

cancelhandle(fh: array of byte): (array of byte, array of byte)
{
	return schedule(sftpclose(fh), ref Req.Ignore (0, nil, 0));
}

# returns (styxbuf, sftpbuf)
dosftp(mm: ref Rsftp): (array of byte, array of byte)
{
	op: ref Req;
	if(tagof mm != tagof Rsftp.Version) {
		op = tabsftp.find(mm.id);
		if(op != nil) {
			tabsftp.del(op.seq);
			tabstyx.del(op.m.tag);
		} else
			warn(sprint("id %d not registered?", mm.id));

		if(op.canceled) {
			say("request cancelled, cleaning up");
			pick m := mm {
			Handle =>	return cancelhandle(m.fh);
			}
			return (nil, nil);
		}

		if(tagof op == tagof Req.Ignore)
			return (nil, nil);
	}

	pick m := mm {
	Version =>
		say("resp version");
		say(sprint("remote version is %d", m.version));

	Status =>
		say("resp status");

		pick o := op {
		Close =>
			nopens--;
			if(m.status != SSH_FX_OK)
				warn("sftp close failed: "+m.errmsg);
			fids.del(o.fid);
			return styxpack(ref Rmsg.Clunk (op.m.tag));
		Read or Readdir =>
			if(m.status == SSH_FX_EOF)
				return styxpack(ref Rmsg.Read (op.m.tag, array[0] of byte));
			return styxerror(op.m, "sftp read failed: "+m.errmsg); # should not happen
		Open or Opendir =>
			nopens--;
			return styxerror(op.m, m.errmsg);
		Stat =>
			return styxerror(op.m, m.errmsg);
		Walk =>
			return styxerror(op.m, m.errmsg);
		* =>
			warn("missing case");
			warn("rsftp: "+m.text());
			warn("tagof req: "+string tagof o);
			raise "missing case";
		}

	Handle =>
		say("resp handle");
		pick o := op {
		Open or Opendir =>
			f := fids.find(o.fid);
			if(f == nil)
				raise "no such fid?";
			f.fh = m.fh;
			f.mode = o.mode;
			qtype := Sys->QTFILE;
			if(tagof o == tagof Req.Opendir)
				qtype = Sys->QTDIR;
			qid := Sys->Qid (big pathgen++, 0, qtype);
			iounit := 1024; # xxx
			return styxpack(ref Rmsg.Open (op.m.tag, qid, iounit));
		* =>
			(nil, sftpbuf) := cancelhandle(m.fh);
			(styxbuf, nil) := styxerror(op.m, "unexpected sftp handle message");
			return (styxbuf, sftpbuf);
		}

	Data =>
		say("resp data");
		pick o := op {
		Read =>	return styxpack(ref Rmsg.Read (op.m.tag, m.buf));
		* =>	return styxerror(op.m, "unexpected sftp data message");
		}

	Name =>
		say("resp name");
		pick o := op {
		Readdir =>
			f := fids.find(o.rm.fid);
			dirs: list of ref Sys->Dir;
			for(i := 0; i < len m.attrs; i++)
				if(m.attrs[i].name != "." && m.attrs[i].name != "..")
					dirs = ref m.attrs[i].dir(nil)::dirs;
			f.dirs = dirs;

			data := array[0] of byte;
			while(f.dirs != nil) {
				buf := styx->packdir(*hd f.dirs);
				if(len data+len buf > o.rm.count)
					break;
				data = add(data, buf);
				f.dirs = tl f.dirs;
			}
			return styxpack(ref Rmsg.Read (op.m.tag, data));
		* =>
			return styxerror(op.m, "unexpected sftp name message");
		}

	Attrs =>
		say("resp attrs");
		pick o := op {
		Walk =>
			say("op.walk");
			# xxx if we walk from a file to e.g. ../../.. this would be wrong.
			qids := array[len o.wm.names] of Sys->Qid;
			for(i := 0; i < len o.wm.names; i++)
				qids[i] = Sys->Qid (big pathgen++, 0, Sys->QTDIR);
			if(!m.attr.isdir())
				qids[len qids-1].qtype = Sys->QTFILE;
			nf := ref Fid (o.wm.newfid, nil, 0, m.attr.isdir(), o.npath, nil, m.attr);
			fids.add(o.wm.newfid, nf);
			say("op.walk done, fid "+nf.text());
			return styxpack(ref Rmsg.Walk (op.m.tag, qids));
		Stat =>
			say("op.stat");
			f := fids.find(o.sm.fid);
			say("attrs for op.stat, attrs "+m.attr.text());
			dir := m.attr.dir(str->splitstrr(f.path, "/").t1);
			return styxpack(ref Rmsg.Stat (o.m.tag, dir));
		* =>
			return styxerror(op.m, "unexpected sftp attrs message");
		}
	* =>
		say("other reply?");
		raise "missing case";
	}
	return (nil, nil);
}

# returns either a styx response, or an sftp message
dostyx(gm: ref Tmsg): (array of byte, array of byte)
{
	om: ref Rmsg;
	say(sprint("dostyx, tag %d, %s", tagof gm, gm.text()));

	pick m := gm {
	Version =>
		# xxx should enforce this is the first message.
		# xxx should enforce NOTAG
		if(m.version != "9P2000")
			return styxerror(m, "unknown");
		msize := min(2*1024, m.msize); # xxx sensible?
		say(sprint("using msize %d", msize));
		om = ref Rmsg.Version (m.tag, msize, "9P2000");

	Auth =>
		return styxerror(m, "no auth required");

	Attach =>
		f := fids.find(m.fid);
		if(f != nil)
			return styxerror(m, "fid already in use");
		f = ref Fid (m.fid, nil, 0, 1, "/", nil, nil);
		fids.add(m.fid, f);
		qid := Sys->Qid (big 0, 0, Sys->QTDIR);
		om = ref Rmsg.Attach (m.tag, qid);

	Flush =>
		req := tabstyx.find(m.oldtag);
		if(req != nil) {
			tabstyx.del(m.oldtag);
			req.canceled = 1;
			# xxx cancel the action of the old styx message
		}
		om = ref Rmsg.Flush (m.tag);

	Walk =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		nf := fids.find(m.newfid);
		if(nf != nil)
			return styxerror(m, "newfid already in use");
		if(len m.names == 0) {
			nf = ref Fid (m.newfid, nil, 0, f.isdir, f.path, nil, nil);
			fids.add(nf.fid, nf);
			return styxpack(ref Rmsg.Walk (m.tag, nil));
		}
		npath := pathjoin(f.path, m.names);
		say(sprint("walk, npath %q", npath));

		return schedule(sftpstat(npath), ref Req.Walk (0, m, 0, npath, m));

	Open =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(m.mode & ~(Sys->OREAD|Sys->OWRITE))
			return styxerror(m, "mode not supported");
		if(f.fh != nil)
			return styxerror(m, "already open");

		nopens++;
		if(f.isdir)
			return schedule(sftpopendir(f.path), ref Req.Opendir (0, m, 0, m.fid, m.mode));
		else
			return schedule(sftpopen(f.path, m.mode, f.attr), ref Req.Open (0, m, 0, m.fid, m.mode));

	Create =>
		# if dir, mkdir.  otherwise, open with create flag
		#fid: int;
		#name: string;
		#perm, mode: int;
		return styxerror(m, "read-only for now");

	Read =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(f.fh == nil)
			return styxerror(m, "not open");
		if(f.isdir) {
			if(m.offset > big 0) {
				data := array[0] of byte;
				while(f.dirs != nil) {
					buf := styx->packdir(*hd f.dirs);
					if(len data+len buf > m.count)
						break;
					data = add(data, buf);
					f.dirs = tl f.dirs;
				}
				# if we had nothing cached, and we haven't seen eof yet, do another request.
				return styxpack(ref Rmsg.Read (m.tag, data));
			}
			return schedule(sftpreaddir(f.fh), ref Req.Readdir (0, m, 0, m));
		} else {
			say(sprint("read, f.mode %o, Sys->OREAD %o", f.mode, Sys->OREAD));
			if(f.mode != Sys->OREAD && f.mode != Sys->ORDWR)
				return styxerror(m, "not open for reading");
			return schedule(sftpread(f.fh, m.offset, m.count), ref Req.Read (0, m, 0, m));
		}
		
	Write =>
		# just write
		#fid: int;
		#offset: big;
		#data: array of byte;
		return styxerror(m, "read-only for now");

	Clunk =>
		say(sprint("clunk, fid %d", m.fid));
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		# xxx there might be an Open in transit!
		if(f.fh != nil)
			return schedule(sftpclose(f.fh), ref Req.Close (0, m, 0, m.fid));
		fids.del(m.fid);
		om = ref Rmsg.Clunk (m.tag);

	Stat =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		return schedule(sftpstat(f.path), ref Req.Stat (0, m, 0, m));

	Remove => 
		# if dir, rmdir.  otherwise remove
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		# xxx there might be an Open in transit!
		nopens--;
		if(f.fh != nil)
			return schedule(sftpclose(f.fh), ref Req.Ignore (0, m, 0));
		fids.del(m.fid); # xxx have to look at what happens when fid is still in use
		return styxerror(m, "read-only for now");

	Wstat =>
		# setstat
		#fid: int;
		#stat: Sys->Dir;
		return styxerror(m, "read-only for now");

	* =>
		raise "missing case";
	}

	if(om == nil)
		raise "nothing to send?";
	return styxpack(om);
}

schedule(idbuf: (int, array of byte), req: ref Req): (array of byte, array of byte)
{
	(id, buf) := idbuf;
	req.seq = id;
	tabsftp.add(req.seq, req);
	tabstyx.add(req.m.tag, req);
	return (nil, buf);
}

styxpack(om: ref Rmsg): (array of byte, array of byte)
{
	if(Dflag)
		warn("-> "+om.text());
	return (om.pack(), nil);
}

styxerror(m: ref Tmsg, s: string): (array of byte, array of byte)
{
	return styxpack(ref Rmsg.Error(m.tag, s));
}

add(a, b: array of byte): array of byte
{
	n := array[len a+len b] of byte;
	n[:] = a;
	n[len a:] = b;
	return n;
}

sftpnames := array[] of {
"", "init", "version", "open", "close", "read", "write", "lstat", "fstat", "setstat", "fsetstat", "opendir", "readdir", "remove", "mkdir", "rmdir", "realpath", "stat", "rename", "readlink", "symlink",
};

sftppack(t: int, a: array of ref Val): (int, array of byte)
{
	id := sftpgen++;
	na := array[2+len a] of ref Val;
	na[0] = valbyte(byte t);
	na[1] = valint(id);
	na[2:] = a;
	buf := sshlib->packvals(na, 1);
	say(sprint("sftpwrite, type %d %s, len buf %d", t, sftpnames[t], len buf));
	say("sftp packet:");
	hexdump(buf);
	return (id, buf);
}

sftpopendir(path: string): (int, array of byte)
{
	v := array[] of {valstr(path)};
	return sftppack(SSH_FXP_OPENDIR, v);
}

sftpopen(path: string, mode: int, attr: ref Attr): (int, array of byte)
{
	pflags := 0;
	if(mode & Sys->OREAD)
		pflags |= SSH_FXF_READ;
	if(mode & Sys->OWRITE)
		pflags |= SSH_FXF_WRITE;
	v := array[2+len attr.vals] of ref Val;
	v[0] = valstr(path);
	v[1] = valint(pflags);
	v[2:] = attr.vals;
	return sftppack(SSH_FXP_OPEN, v);
}

statflags := SSH_FILEXFER_ATTR_SIZE|SSH_FILEXFER_ATTR_UIDGID|SSH_FILEXFER_ATTR_PERMISSIONS|SSH_FILEXFER_ATTR_ACMODTIME;
sftpstat(path: string): (int, array of byte)
{
	v := array[] of {valstr(path), valint(statflags)};
	return sftppack(SSH_FXP_STAT, v);
}

sftpreaddir(fh: array of byte): (int, array of byte)
{
	v := array[] of {valbytes(fh)};
	return sftppack(SSH_FXP_READDIR, v);
}

sftpclose(fh: array of byte): (int, array of byte)
{
	v := array[] of {valbytes(fh)};
	return sftppack(SSH_FXP_CLOSE, v);
}

sftpread(fh: array of byte, off: big, n: int): (int, array of byte)
{
	v := array[] of {valbytes(fh), valbig(off), valint(n)};
	return sftppack(SSH_FXP_READ, v);
}


pathjoin(base: string, a: array of string): string
{
	s := base;
	if(s == "/")
		s = "";
	for(i := 0; i < len a; i++)
		s += "/"+a[i];
	if(s == nil)
		s = "/";
	return s;
}

g32(d: array of byte): int
{
	v := 0;
	v = v<<8|int d[0];
	v = v<<8|int d[1];
	v = v<<8|int d[2];
	v = v<<8|int d[3];
	return v;
}

killgrp(pid: int)
{
	progctl(pid, "killgrp");
}

progctl(pid: int, ctl: string)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "%s", ctl);
}

min(a, b: int): int
{
	if(a < b)
		return a;
	return b;
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "sftpfs: %s\n", s);
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
