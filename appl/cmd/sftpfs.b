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

packetch: chan of (array of byte, string);

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

	cfg := Cfg.default();
	keyspec: string;
	arg->init(args);
	arg->setusage(arg->progname()+" [-dD] [-e enc-algs] [-m mac-algs] [-K kex-algs] [-H hostkey-algs] [-C compr-algs] [-k keyspec] addr");
	while((ch := arg->opt()) != 0)
		case ch {
		'D' =>	Dflag++;
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		'e' or 'm' or 'K' or 'H' or 'C' =>
			err := cfg.setopt(ch, arg->earg());
			if(err != nil)
				fail(err);
		'k' =>	keyspec = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	addr := hd args;

	sys->pctl(Sys->NEWPGRP, nil);

	packetch = chan of (array of byte, string);
	msgc := chan of ref Tmsg;
	fids = fids.new(32, nil);
	tabsftp = tabsftp.new(32, nil);
	tabstyx = tabstyx.new(32, nil);

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	(c, lerr) := Sshc.login(conn.dfd, addr, keyspec, cfg);
	if(lerr != nil)
		fail(lerr);
	say("logged in");
	sshc = c;

	msg := array[] of {
		valstr("session"),
		valint(0),  # channel
		valint(1*1024*1024),  # window size
		valint(32*1024),  # max packet size
	};
	ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, msg);

	time0 = daytime->now();

	spawn sshreader(c);
	spawn styxreader(sys->fildes(0), msgc);
	spawn main(msgc, c);
}

main(msgc: chan of ref Tmsg, c: ref Sshc)
{
done:
	for(;;) alt {
	gm := <-msgc =>
		if(gm == nil)
			break done;
		pick m := gm {
		Readerror =>
			warn("read error: "+m.error);
			break done;
		}
		dostyx(gm);

	(d, err) := <-packetch =>
		if(err != nil)
			fail(err);

		dossh(c, d);
	}
	killgrp(sys->pctl(0, nil));
}

dossh(c: ref Sshc, d: array of byte)
{
	t := int d[0];
	d = d[1:];
	case t {
	Sshlib->SSH_MSG_DISCONNECT =>
		discmsg := list of {Tint, Tstr, Tstr};
		msg := eparsepacket(d, discmsg);
		say("ssh disconnect:");
		say("reason: "+msg[0].text());
		say("descr: "+msg[1].text());
		say("language: "+msg[2].text());

	Sshlib->SSH_MSG_IGNORE =>
		msg := eparsepacket(d, list of {Tstr});
		say("ssh ignore, data: "+getstr(msg[0]));

	Sshlib->SSH_MSG_DEBUG =>
		msg := eparsepacket(d, list of {Tbool, Tstr, Tstr});
		say("ssh debug, text: "+getstr(msg[1]));

	Sshlib->SSH_MSG_UNIMPLEMENTED =>
		msg := eparsepacket(d, list of {Tint});
		pktno := getint(msg[0]);
		fail(sprint("packet %d is not implemented at remote...", pktno));

	Sshlib->SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
		say("ssh 'channel open confirmation'");
		# byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		# uint32    recipient channel
		# uint32    sender channel
		# uint32    initial window size
		# uint32    maximum packet size
		# ....      channel type specific data follows
		msg := eparsepacket(d, list of {Tint, Tint, Tint, Tint});
		# xxx can recipient/sender channel be different?
		# xxx should keep track of window size & max packet size

		say("writing 'subsystem' channel request");
		omsg := array[] of {
			valint(0),
			valstr("subsystem"),
			valbool(1),  # want reply
			valstr("sftp"),
		};
		ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, omsg);
		say("wrote request to execute command");

	Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
		say("ssh 'channel success'");
		eparsepacket(d, list of {Tint});

		sftpmsg := array[] of {valbyte(byte SSH_FXP_INIT), valint(3)};
		omsg := array[] of {valint(0), valbytes(packpacket(sftpmsg))};
		ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_DATA, omsg);

	Sshlib->SSH_MSG_CHANNEL_FAILURE =>
		say("ssh 'channel failure'");
		eparsepacket(d, list of {Tint});
		fail("channel failure");

	Sshlib->SSH_MSG_CHANNEL_DATA =>
		say("ssh 'tunnel data'");
		# byte      SSH_MSG_CHANNEL_DATA
		# uint32    recipient channel
		# string    data
		msg := eparsepacket(d, list of {Tint, Tstr});
		# xxx should verify channel is as expected

		say("channel data:");
		buf := getbytes(msg[1]);
		if(sys->write(sys->fildes(1), buf, len buf) != len buf)
			fail(sprint("write: %r"));

		# xxx assuming one sftp packet per ssh-message.  bogus.
		(m, err) := Rsftp.parse(buf);
		if(err != nil)
			fail("parsing sftp response message: "+err);
		dosftp(m);

	Sshlib->SSH_MSG_CHANNEL_EXTENDED_DATA =>
		say("ssh 'channel extended data'");
		# byte      SSH_MSG_CHANNEL_EXTENDED_DATA
		# uint32    recipient channel
		# uint32    data_type_code
		# string    data
		msg := eparsepacket(d, list of {Tint, Tint, Tstr});
		ch := getint(msg[0]);
		datatype := getint(msg[1]);
		data := getbytes(msg[2]);
		
		case datatype {
		Sshlib->SSH_EXTENDED_DATA_STDERR =>
			say("stderr data");
			buf := getbytes(msg[2]);
			if(0 && sys->write(sys->fildes(2), buf, len buf) != len buf)
				fail(sprint("write: %r"));
		}
		# ignore other data

	Sshlib->SSH_MSG_CHANNEL_EOF =>
		say("ssh 'channel eof'");
		msg := eparsepacket(d, list of {Tint});
		ch := getint(msg[0]);

	Sshlib->SSH_MSG_CHANNEL_CLOSE =>
		say("ssh 'channel close'");
		msg := eparsepacket(d, list of {Tint});
		ch := getint(msg[0]);
		return;

	Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
		say("ssh 'channel open failure'");
		msg := eparsepacket(d, list of {Tint, Tint, Tstr, Tstr});
		ch := getint(msg[0]);
		code := getint(msg[1]);
		reason := getstr(msg[2]);
		lang := getstr(msg[3]);
		fail("channel open failure: "+reason);

	Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
		say("ssh 'channel window adjust'");
		msg := eparsepacket(d, list of {Tint, Tint});
		ch := getint(msg[0]);
		nbytes := getint(msg[1]); # bytes to add
	* =>
		say(sprint("ssh, other packet type %d, len data %d", int t, len d));
	}
}

sshreader(c: ref Sshc)
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

styxreader(fd: ref Sys->FD, msgc: chan of ref Tmsg)
{
	for(;;) {
		m := Tmsg.read(fd, 8*1024); # xxx
		msgc <-= m;
		if(tagof m == tagof Tmsg.Readerror)
			return;
	}
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
	d.qid = Sys->Qid (big pathgen++, 0, Sys->QTDIR);
	if(a.isdir())
		d.qid.qtype = Sys->QTDIR;
	d.mode = a.perms&8r777;
	if(a.isdir())
		d.mode |= Sys->DMDIR;
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

	parse:	fn(d: array of byte): (ref Rsftp, string);
	text:	fn(m: self ref Rsftp): string;
};

Rsftp.parse(d: array of byte): (ref Rsftp, string)
{
	# fields in attrs
	lattrs := list of {Tint, Tbig, Tint, Tint, Tint, Tint, Tint};

	say(sprint("rsftp.parse, len d %d, buf:", len d));
	hexdump(d);

	hdrsize := 4+1;
	if(len d < hdrsize)
		return (nil, "short sftp message");
	msg := eparsepacket(d[:hdrsize], list of {Tint, Tbyte});

	length := getint(msg[0]);
	if(len d-4 != length)
		return (nil, sprint("malsized message, expect %d, have %d", length, len d-4));
	t := int getbyte(msg[1]);
	say(sprint("sftp msg, length %d, t %d", length, t));

	body := d[hdrsize:];
	m: ref Rsftp;
	case t {
	SSH_FXP_VERSION =>
		# xxx can there be extensions, should parse those too.
		msg = eparsepacket(body[:4], list of {Tint});
		m = ref Rsftp.Version (0, getint(msg[0]));

	SSH_FXP_STATUS =>
		msg = eparsepacket(body, list of {Tint, Tint, Tstr, Tstr});
		m = ref Rsftp.Status (getint(msg[0]), getint(msg[1]), getstr(msg[2]), getstr(msg[3]));
		# if(status < 0 || status > xxx)
		# 	return (nil, sprint("unknown status type %d", t));

	SSH_FXP_HANDLE =>
		msg = eparsepacket(body, list of {Tint, Tstr});
		m = ref Rsftp.Handle (getint(msg[0]), getbytes(msg[1]));

	SSH_FXP_DATA =>
		msg = eparsepacket(body, list of {Tint, Tstr});
		m = ref Rsftp.Data (getint(msg[0]), getbytes(msg[1]));

	SSH_FXP_NAME =>
		msg = eparsepacket(body[:8], list of {Tint, Tint});
		id := getint(msg[0]);
		nattr := getint(msg[1]);
		say(sprint("names has %d entries", nattr));

		multiattrs: list of int;
		for(i := 0; i < nattr; i++)
			multiattrs = Tstr::Tstr::Tint::Tbig::Tint::Tint::Tint::Tint::Tint::multiattrs;
		stat := eparsepacket(body[8:], multiattrs);
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
		msg = eparsepacket(body, Tint::lattrs);
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

cancelhandle(fh: array of byte)
{
	schedule(ref Req.Ignore (sftpclose(fh), nil, 0));
}

dosftp(mm: ref Rsftp)
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
			Handle =>	cancelhandle(m.fh);
			}
			return;
		}

		if(tagof op == tagof Req.Ignore)
			return;
	}

	pick m := mm {
	Version =>
		say("resp version");
		say(sprint("remote version is %d", m.version));

	Status =>
		say("resp status");

		pick o := op {
		Close =>
			if(m.status != SSH_FX_OK)
				warn("sftp close failed: "+m.errmsg);
			fids.del(o.fid);
			return reply(ref Rmsg.Clunk (op.m.tag));
		Read or Readdir =>
			if(m.status == SSH_FX_EOF)
				return reply(ref Rmsg.Read (op.m.tag, array[0] of byte));
			return replyerror(op.m, "sftp read failed: "+m.errmsg); # should not happen
		Open or Opendir =>
			return replyerror(op.m, "open failed: "+m.errmsg);
		Stat =>
			return replyerror(op.m, "stat failed: "+m.errmsg);
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
			return reply(ref Rmsg.Open (op.m.tag, qid, iounit));
		* =>
			cancelhandle(m.fh);
			return replyerror(op.m, "unexpected sftp handle message");
		}

	Data =>
		say("resp data");
		pick o := op {
		Read =>	return reply(ref Rmsg.Read (op.m.tag, m.buf));
		* =>	return replyerror(op.m, "unexpected sftp data message");
		}

	Name =>
		say("resp name");
		pick o := op {
		Readdir =>
			f := fids.find(o.rm.fid);
			dirs: list of ref Sys->Dir;
			for(i := 0; i < len m.attrs; i++)
				dirs = ref m.attrs[i].dir(nil)::dirs;
			f.dirs = dirs;

			data := array[0] of byte;
			while(f.dirs != nil) {
				buf := styx->packdir(*hd f.dirs);
				if(len data+len buf <= o.rm.count) {
					data = add(data, buf);
					f.dirs = tl f.dirs;
				}
			}
			return reply(ref Rmsg.Read (op.m.tag, data));
		* =>
			return replyerror(op.m, "unexpected sftp name message");
		}

	Attrs =>
		say("resp attrs");
		pick o := op {
		Walk =>
			say("op.walk");
			qids := array[len o.wm.names] of Sys->Qid;
			for(i := 0; i < len o.wm.names; i++) {
				qtype := Sys->QTDIR;
				# xxx
				#if(i == len o.wm.names-1 && attr.ftype != SSH_FILEXFER_TYPE_DIRECTORY)
				#	qtype = Sys->QTFILE;
				qids[i] = Sys->Qid (big pathgen++, 0, qtype);
			}
			isdir := m.attr.isdir();
			nf := ref Fid (o.wm.newfid, nil, 0, isdir, o.npath, nil, m.attr);
			fids.add(o.wm.newfid, nf);
			say("op.walk done, fid "+nf.text());
			return reply(ref Rmsg.Walk (op.m.tag, qids));
		Stat =>
			say("op.stat");
			f := fids.find(o.sm.fid);
			dir := m.attr.dir(str->splitstrr(f.path, "/").t1);
			return reply(ref Rmsg.Stat (o.m.tag, dir));
		* =>
			return replyerror(op.m, "unexpected sftp attrs message");
		}

	* =>
		say("other reply?");
		raise "missing case";
	}
}


dostyx(gm: ref Tmsg)
{
	om: ref Rmsg;
	say(sprint("dostyx, tag %d, %s", tagof gm, gm.text()));

	pick m := gm {
	Version =>
		# xxx should enforce this is the first message.
		# xxx should enforce NOTAG
		if(m.version != "9P2000")
			return replyerror(m, "unknown");
		msize := min(2*1024, m.msize); # xxx sensible?
		say(sprint("using msize %d", msize));
		om = ref Rmsg.Version (m.tag, msize, "9P2000");

	Auth =>
		replyerror(m, "no auth required");

	Attach =>
		f := fids.find(m.fid);
		if(f != nil)
			return replyerror(m, "fid already in use");
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
			return replyerror(m, "no such fid");
		nf := fids.find(m.newfid);
		if(nf != nil)
			return replyerror(m, "newfid already in use");
		npath := f.path+pathjoin(m.names);
		say(sprint("walk, npath %q", npath));

		return schedule(ref Req.Walk (sftpstat(npath), m, 0, npath, m));

	Open =>
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		if(m.mode & ~(Sys->OREAD|Sys->OWRITE))
			return replyerror(m, "mode not supported");
		if(f.fh != nil)
			return replyerror(m, "already open");

		if(f.isdir)
			return schedule(ref Req.Opendir (sftpopendir(f.path), m, 0, m.fid, m.mode));
		else
			return schedule(ref Req.Open (sftpopen(f.path, m.mode, f.attr), m, 0, m.fid, m.mode));

	Create =>
		# if dir, mkdir.  otherwise, open with create flag
		#fid: int;
		#name: string;
		#perm, mode: int;
		return replyerror(m, "read-only for now");

	Read =>
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		if(f.fh == nil)
			return replyerror(m, "not open");
		if(f.isdir) {
			if(m.offset > big 0) {
				data := array[0] of byte;
				while(f.dirs != nil) {
					buf := styx->packdir(*hd f.dirs);
					if(len data+len buf <= m.count) {
						data = add(data, buf);
						f.dirs = tl f.dirs;
					}
				}
				# if we had nothing cached, and we haven't seen eof yet, do another request.
				return reply(ref Rmsg.Read (m.tag, data));
			}
			return schedule(ref Req.Readdir (sftpreaddir(f.fh), m, 0, m));
		} else {
			say(sprint("read, f.mode %o, Sys->OREAD %o", f.mode, Sys->OREAD));
			if(f.mode != Sys->OREAD && f.mode != Sys->ORDWR)
				return replyerror(m, "not open for reading");
			return schedule(ref Req.Read (sftpread(f.fh, m.offset, m.count), m, 0, m));
		}
		
	Write =>
		# just write
		#fid: int;
		#offset: big;
		#data: array of byte;
		return replyerror(m, "read-only for now");

	Clunk =>
		say(sprint("clunk, fid %d", m.fid));
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		if(f.fh != nil)
			return schedule(ref Req.Close (sftpclose(f.fh), m, 0, m.fid));
		fids.del(m.fid);
		om = ref Rmsg.Clunk (m.tag);

	Stat =>
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		return schedule(ref Req.Stat (sftpstat(f.path), m, 0, m));

	Remove => 
		# if dir, rmdir.  otherwise remove
		#fid: int;
		# xxx remove fid
		fids.del(m.fid); # xxx have to look at what happens when fid is still in use
		return replyerror(m, "read-only for now");

	Wstat =>
		# setstat
		#fid: int;
		#stat: Sys->Dir;
		return replyerror(m, "read-only for now");

	* =>
		raise "missing case";
	}

	if(om == nil)
		raise "nothing to send?";
	reply(om);
}

schedule(req: ref Req)
{
	tabsftp.add(req.seq, req);
	tabstyx.add(req.m.tag, req);
}

reply(om: ref Rmsg)
{
	buf := om.pack();
	n := sys->write(sys->fildes(0), buf, len buf);
	if(n != len buf)
		fail(sprint("write: %r"));
}

replyerror(m: ref Tmsg, s: string)
{
	om := ref Rmsg.Error(m.tag, s);
	buf := om.pack();
	n := sys->write(sys->fildes(0), buf, len buf);
	if(n != len buf)
		fail(sprint("write: %r"));
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

sftpwrite(t: int, a: array of ref Val): int
{
	id := sftpgen++;
	na := array[2+len a] of ref Val;
	na[0] = valbyte(byte t);
	na[1] = valint(id);
	na[2:] = a;
	buf := packpacket(na);
	say(sprint("sftpwrite, type %d %s, len buf %d, length %d", t, sftpnames[t], len buf, g32(buf)));
	say("sftp packet");
	hexdump(buf);
	vals := array[] of {
		valint(0),
		valbytes(buf),
	};
	ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_DATA, vals);
	return id;
}

sftpopendir(path: string): int
{
	v := array[] of {valstr(path)};
	return sftpwrite(SSH_FXP_OPENDIR, v);
}

sftpopen(path: string, mode: int, attr: ref Attr): int
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
	return sftpwrite(SSH_FXP_OPEN, v);
}

statflags := SSH_FILEXFER_ATTR_SIZE|SSH_FILEXFER_ATTR_UIDGID|SSH_FILEXFER_ATTR_PERMISSIONS|SSH_FILEXFER_ATTR_ACMODTIME;
sftpstat(path: string): int
{
	v := array[] of {valstr(path), valint(statflags)};
	return sftpwrite(SSH_FXP_STAT, v);
}

sftpreaddir(fh: array of byte): int
{
	v := array[] of {valbytes(fh)};
	return sftpwrite(SSH_FXP_READDIR, v);
}

sftpclose(fh: array of byte): int
{
	v := array[] of {valbytes(fh)};
	return sftpwrite(SSH_FXP_CLOSE, v);
}

sftpread(fh: array of byte, off: big, n: int): int
{
	v := array[] of {valbytes(fh), valbig(off), valint(n)};
	return sftpwrite(SSH_FXP_READ, v);
}

packpacket(a: array of ref Val): array of byte
{
	size := 0;
	for(i := 0; i < len a; i++)
		size += a[i].size();
	buf := array[4+size] of byte;
	p32(buf, size);
	o := 4;
	for(i = 0; i < len a; i++)
		o += a[i].packbuf(buf[o:]);
	return buf;
}

g32(d: array of byte): int
{
	v := int d[0];
	v = v<<8|int d[1];
	v = v<<8|int d[2];
	v = v<<8|int d[3];
	return v;
}

p32(d: array of byte, v: int)
{
	d[0] = byte (v>>24);
	d[1] = byte (v>>16);
	d[2] = byte (v>>8);
	d[3] = byte (v>>0);
}

pathjoin(a: array of string): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += "/"+a[i];
	return s;
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

max(a, b: int): int
{
	if(a < b)
		return b;
	return a;
}

min(a, b: int): int
{
	if(a < b)
		return a;
	return b;
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
