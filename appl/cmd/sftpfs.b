implement Sftpfs;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
include "string.m";
	str: String;
include "sh.m";
	sh: Sh;
include "keyring.m";
include "tables.m";
	tables: Tables;
	Table: import tables;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import styx;
include "../lib/sshlib.m";
	sshlib: Sshlib;
	Val: import sshlib;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshlib;
	getbool, getbyte, getint, getbig, getipint, getstr, getbytes: import sshlib;
	valbyte, valbool, valint, valbig, valnames, valstr, valbytes, valmpint: import sshlib;
include "util0.m";
	util: Util0;
	hex, rev, min, pid, killgrp, warn, g32i: import util;
include "sftp.m";

Sftpfs: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


Sftpversion: con 3;
Handlemaxlen: con 256;
POSIX_S_IFDIR: con 8r0040000;

dflag: int;

Pktlenmax: con 34000;
Statflags: con SSH_FILEXFER_ATTR_SIZE|SSH_FILEXFER_ATTR_UIDGID|SSH_FILEXFER_ATTR_PERMISSIONS|SSH_FILEXFER_ATTR_ACMODTIME;

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
	Open or
	Opendir or
	Create =>
		fid, mode:	int;
	Mkdir =>
		fid, mode:	int;
		path:	string;
	Stat =>		sm:	ref Tmsg.Stat;
	Read or
	Readdir =>	rm:	ref Tmsg.Read;
	Write =>
		wm:	ref Tmsg.Write;
		length:	int;
	Close =>	fid:	int;
	Setstat1 or
	Setstat2 =>
		wm:	ref Tmsg.Wstat;
	Remove =>
		rm:	ref Tmsg.Remove;
	Ignore =>
	}
};

Attr: adt {
	name:	string;
	flags:	int;
	size:	big;
	owner, group:	string;
	perms:	int;
	atime, mtime:	int;

	new:	fn(isdir: int): ref Attr;
	mk:	fn(name: string, a: array of ref Val): ref Attr;
	isdir:	fn(a: self ref Attr): int;
	dir:	fn(a: self ref Attr, name: string): Sys->Dir;
	text:	fn(a: self ref Attr): string;
};


fids: ref Table[ref Fid];  # tmsg.fid
tabsftp: ref Table[ref Req];  # sftp seq
tabstyx: ref Table[ref Req];  # tmsg.tag
sftpgen := 1;
pathgen := 0;
nopens:	int;

readstyxc,
styxwrotec,
readsftpc,
sftpwrotec:	chan of int;

styxreadc:	chan of ref Tmsg;
writestyxc:	chan of ref Rmsg;
sftpreadc:	chan of (ref Rsftp, string);
writesftpc:	chan of array of byte; # packed message

sshcmd: string;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	str = load String String->PATH;
	sh = load Sh Sh->PATH;
	sh->initialise();
	styx = load Styx Styx->PATH;
	styx->init();
	tables = load Tables Tables->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sshlib = load Sshlib Sshlib->PATH;
	sshlib->init();

	sys->pctl(Sys->NEWPGRP, nil);

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] [-s sshcmd | addr]");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
		's' =>	sshcmd = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args == 1 && sshcmd != nil || len args == 0 && sshcmd == nil)
		arg->usage();
	if(len args == 1)
		sshcmd = sprint("ssh -s sftp %q", hd args);

	readstyxc = chan of int;
	styxwrotec = chan of int;
	readsftpc = chan of int;
	sftpwrotec = chan of int;

	styxreadc = chan of ref Tmsg;
	writestyxc = chan of ref Rmsg;
	sftpreadc = chan of (ref Rsftp, string);
	writesftpc = chan of array of byte; # packed message

	(tosftpfd, fromsftpfd) := run(sshcmd);

	initmsg := array[] of {valbyte(byte SSH_FXP_INIT), valint(Sftpversion)};
	buf := sshlib->packvals(initmsg, 1);
	if(sys->write(tosftpfd, buf, len buf) != len buf)
		fail(sprint("writing sftp version: %r"));

	fids = fids.new(31, nil);
	tabsftp = tabsftp.new(31, nil);
	tabstyx = tabstyx.new(31, nil);

	styxfd := sys->fildes(0);

	spawn styxreader(styxfd);
	spawn styxwriter(styxfd);
	spawn sftpreader(fromsftpfd);
	spawn sftpwriter(tosftpfd);
	spawn main();
}

run(cmd: string): (ref Sys->FD, ref Sys->FD)
{
	if(sys->pipe(tossh := array[2] of ref Sys->FD) != 0)
		fail(sprint("pipe: %r"));
	if(sys->pipe(fromssh := array[2] of ref Sys->FD) != 0)
		fail(sprint("pipe: %r"));
	spawn run0(cmd, tossh[1], fromssh[0]);
	return (tossh[0], fromssh[1]);
}

run0(cmd: string, fd0, fd1: ref Sys->FD)
{
	sys->pctl(Sys->NEWFD, list of {fd0.fd, fd1.fd, 2});
	sys->dup(fd0.fd, 0);
	sys->dup(fd1.fd, 1);
	fd0 = fd1 = nil;
	err := sh->system(nil, cmd);
	if(err != nil)
		warn("ssh: "+err);
}

styxreader(fd: ref Sys->FD)
{
	for(;;) {
		<-readstyxc;
		styxreadc <-= m := Tmsg.read(fd, Styx->MAXRPC); # xxx
		if(m == nil)
			break;
	}
}

styxwriter(fd: ref Sys->FD)
{
	for(;;) {
		m := <-writestyxc;
		if(m == nil)
			break;
		if(sys->write(fd, buf := m.pack(), len buf) != len buf)
			fail(sprint("styx write: %r")); # xxx perhaps signal to main and do some clean up?
		styxwrotec <-= 0;
	}
}

sftpreader(fd: ref sys->FD)
{
	for(;;) {
		<-readsftpc;
		(m, err) := Rsftp.read(fd);
		sftpreadc <-= (m, err);
		if(m == nil || err != nil)
			break;
	}
}

sftpwriter(fd: ref Sys->FD)
{
	for(;;) {
		buf := <-writesftpc;
		if(sys->write(fd, buf, len buf) != len buf)
			fail(sprint("sftp write: %r")); # xxx signal to main, for cleanup?
		sftpwrotec <-= 0;
	}
}

styxwriting := 0;
sftpwriting := 0;
styxwaiting := 0;
sftpwaiting := 0;

handle(t: (ref Rmsg, array of byte))
{
	(xm, sm) := t;
	if(xm != nil) {
		if(styxwriting) {
			<-styxwrotec;
			styxwriting--;
		}
		writestyxc <-= xm;
		styxwriting++;
	}

	if(sm != nil) {
		if(sftpwriting) {
			<-sftpwrotec;
			sftpwriting--;
		}
		writesftpc <-= sm;
		sftpwriting++;
	}
}

kick()
{
	if(styxwaiting && sftpwriting == 0) {
		styxwaiting--;
		readstyxc <-= 0;
	}

	if(sftpwaiting && styxwriting == 0) {
		sftpwaiting--;
		readsftpc <-= 0;
	}
}

main()
{
	readstyxc <-= 1;
	readsftpc <-= 1;

done:
	for(;;) alt {
	mm := <-styxreadc =>
say("main: styxreadc");
		if(mm == nil)
			break done;
		pick m := mm {
		Readerror =>
			fail("styx read error: "+m.error);
		}

		styxwaiting++;
		handle(dostyx(mm));
		kick();

	<-styxwrotec =>
say("main: styxwrotec");
		styxwriting--;
		kick();

	(m, err) := <-sftpreadc =>
say("main: sftpreadc");
		if(err != nil)
			fail("sftp read: "+err);

		sftpwaiting++;
		handle(dosftp(m));
		kick();

	<-sftpwrotec =>
say("main: sftpwrotec");
		sftpwriting--;
		kick();
	}
	warn("main: done");
	killgrp(pid());
}


Fid.text(f: self ref Fid): string
{
	return sprint("Fid (fid %d, fh %d, mode %o, isdir %d, path %q, len dirs %d, attr %s)", f.fid, f.fh != nil, f.mode, f.isdir, f.path, len f.dirs, f.attr.text());
}

Attr.isdir(a: self ref Attr): int
{
	return a.perms&POSIX_S_IFDIR;
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


Attr.new(isdir: int): ref Attr
{
	a := ref Attr (
		"",
		Statflags,
		big 0,
		"", "",  # owner, group
		8r666,
		0, 0  # atime, mtime
	);
	if(isdir)
		a.perms = 8r777|POSIX_S_IFDIR;
	return a;
}

Attr.mk(name: string, a: array of ref Val): ref Attr
{
	flags := getint(a[0]);
	size := getbig(a[1]);
	owner := string getint(a[2]);
	group := string getint(a[3]);
	perms := getint(a[4]);
	atime := getint(a[5]);
	mtime := getint(a[6]);
	attr := ref Attr (name, flags, size, owner, group, perms, atime, mtime);
	return attr;
}

Attr.text(a: self ref Attr): string
{
	return sprint("Attr (name %q, size %bd, uid/gid %q %q mode %o isdir %d atime %d mtime %d", a.name, a.size, a.owner, a.group, a.perms&8r777, a.isdir(), a.atime, a.mtime);
}


Rsftp: adt {
	id:	int;  # bogus for Version
	pick {
	Version =>
		version:	int;
		exts:		list of ref (string, string);
	Status =>
		status:	int;
		errmsg, lang:	string;
	Handle =>	fh:	array of byte;
	Data =>		buf:	array of byte;
	Name =>		attrs:	array of ref Attr;
	Attrs =>	attr:	ref Attr;
	}

	read:	fn(fd: ref Sys->FD): (ref Rsftp, string);
	parse:	fn(buf: array of byte): (ref Rsftp, string);
	text:	fn(m: self ref Rsftp): string;
};

xreadn(fd: ref Sys->FD, buf: array of byte, n: int): string
{
	nn := sys->readn(fd, buf, n);
	if(nn < 0)
		return sprint("%r");
	if(nn == 0)
		return "eof";
	if(n != nn)
		return "short read";
	return nil;
}

Rsftp.read(fd: ref Sys->FD): (ref Rsftp, string)
{
	err := xreadn(fd, length := array[4] of byte, len length);
	if(err != nil)
		return (nil, err);
	(n, nil) := g32i(length, 0);
	if(n == 0)
		return (nil, nil);
	err = xreadn(fd, buf := array[n] of byte, len buf);
	if(err != nil)
		return (nil, err);
	return Rsftp.parse(buf);
}

Rsftp.parse(buf: array of byte): (ref Rsftp, string)
{
	{
		return (rsftpparse(buf), nil);
	} exception x {
	"sftp:*" =>
		return (nil, x[5:]);
	}
}

error(s: string)
{
	raise "sftp:"+s;
}

eparse(buf: array of byte, l: list of int): array of ref Val
{
	(r, err) := sshlib->parsepacket(buf, l);
	if(err != nil)
		error(err);
	return r;
}


rsftpparse(buf: array of byte): ref Rsftp
{
	lattrs := list of {Tint, Tbig, Tint, Tint, Tint, Tint, Tint};

	m := eparse(buf[:1], list of {Tbyte});
	t := int getbyte(m[0]);
	buf = buf[1:];

	rm: ref Rsftp;
	case t {
	SSH_FXP_VERSION =>
		m = eparse(buf[:4], list of {Tint});
		version := getint(m[0]);

		o := 4;
		exts: list of ref (string, string);
		while(o < len buf) {
			m = eparse(buf[o:o+4], list of {Tint});
			namelen := getint(m[0]);
			m = eparse(buf[o+4+namelen:o+4+namelen+4], list of {Tint});
			datalen := getint(m[0]);
			m = eparse(buf[o:o+4+namelen+4+datalen], list of {Tstr, Tstr});
			name := getstr(m[0]);
			data := getstr(m[1]);
			exts = ref (name, data)::exts;
			o += 4+namelen+4+datalen;
			say(sprint("sftp extension: name %q, data %q", name, data));
		}
		rm = ref Rsftp.Version (0, version, rev(exts));

	SSH_FXP_STATUS =>
		m = eparse(buf, list of {Tint, Tint, Tstr, Tstr});
		rm = sm := ref Rsftp.Status (getint(m[0]), getint(m[1]), getstr(m[2]), getstr(m[3]));
		if(sm.status < 0 || sm.status >= SSH_FX_MAX)
			error(sprint("unknown status type %d", t));

	SSH_FXP_HANDLE =>
		m = eparse(buf, list of {Tint, Tstr});
		fh := getbytes(m[1]);
		rm = ref Rsftp.Handle (getint(m[0]), fh);
		if(len fh > Handlemaxlen)
			error(sprint("handle too long, max %d, got %d", Handlemaxlen, len fh));

	SSH_FXP_DATA =>
		m = eparse(buf, list of {Tint, Tstr});
		rm = ref Rsftp.Data (getint(m[0]), getbytes(m[1]));

	SSH_FXP_NAME =>
		m = eparse(buf[:8], list of {Tint, Tint});
		id := getint(m[0]);
		nattr := getint(m[1]);
		say(sprint("names has %d entries", nattr));
		buf = buf[8:];

		multiattrs: list of int;
		for(i := 0; i < nattr; i++)
			multiattrs = Tstr::Tstr::Tint::Tbig::Tint::Tint::Tint::Tint::Tint::multiattrs;
		stat := eparse(buf, multiattrs);
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
		rm = ref Rsftp.Name (id, attrs);

	SSH_FXP_ATTRS =>
		m = eparse(buf, Tint::lattrs);
		id := getint(m[0]);
		attr := Attr.mk(nil, m[1:]);
		rm = ref Rsftp.Attrs (id, attr);

	SSH_FXP_EXTENDED or
	SSH_FXP_EXTENDED_REPLY =>
		error("extended (reply) not supported");
	* =>
		error(sprint("unknown reply, type %d", t));
	}
	say("rsftp message: "+rm.text());
	return rm;
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

cancelhandle(fh: array of byte): (ref Rmsg, array of byte)
{
	return schedule(sftpclose(fh), ref Req.Ignore (0, nil, 0));
}

dosftp(mm: ref Rsftp): (ref Rmsg, array of byte)
{
	op: ref Req;
	if(tagof mm != tagof Rsftp.Version) {
		op = tabsftp.find(mm.id);
		if(op != nil) {
			tabsftp.del(op.seq);
			if(op.m != nil)
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
		if(m.version != Sftpversion)
			fail(sprint("remote has different sftp version %d, expected %d", m.version, Sftpversion));

	Status =>
		say("resp status");

		pick o := op {
		Close =>
			nopens--;
			if(m.status != SSH_FX_OK)
				warn("sftp close failed: "+m.errmsg);
			fids.del(o.fid);
			return (ref Rmsg.Clunk (op.m.tag), nil);
		Read or
		Readdir =>
			if(m.status == SSH_FX_EOF)
				return (ref Rmsg.Read (op.m.tag, array[0] of byte), nil);
			return styxerror(op.m, "sftp read failed: "+m.errmsg); # should not happen
		Open or
		Opendir or
		Create =>
			nopens--;
			return styxerror(op.m, m.errmsg);
		Mkdir =>
			if(m.status != SSH_FX_OK) {
				nopens--;
				return styxerror(op.m, m.errmsg);
			}
			return schedule(sftpopendir(o.path), ref Req.Opendir (0, o.m, 0, o.fid, o.mode));
		Stat =>
			return styxerror(op.m, m.errmsg);
		Walk =>
			return styxerror(op.m, m.errmsg);
		Write =>
			if(m.status != SSH_FX_OK)
				return styxerror(op.m, "sftp write failed: "+m.errmsg);
			return (ref Rmsg.Write (op.m.tag, o.length), nil);
		Remove =>
			if(m.status != SSH_FX_OK)
				return styxerror(op.m, "sftp remove failed: "+m.errmsg);
			return (ref Rmsg.Remove (op.m.tag), nil);
		Setstat1 =>
			if(m.status != SSH_FX_OK)
				return styxerror(op.m, "sftp setstat attrs failed: "+m.errmsg);
			f := fids.find(o.wm.fid);
			if(f == nil)
				return styxerror(op.m, "setstat0: cannot find fid anymore");
			# xxx change/invalidate attr for all fids with the path?
			base := str->splitstrr(f.path, "/").t0;
			if(o.wm.stat.name == nil)
				return (ref Rmsg.Wstat (op.m.tag), nil);
			npath := base+"/"+o.wm.stat.name;
			return schedule(sftprename(f.path, npath), ref Req.Setstat2 (0, o.m, 0, o.wm));
		Setstat2 =>
			if(m.status != SSH_FX_OK)
				return styxerror(op.m, "sftp wstat rename failed: "+m.errmsg);
			return (ref Rmsg.Wstat (op.m.tag), nil);
		* =>
			warn("missing case");
			warn("rsftp: "+m.text());
			warn("tagof req: "+string tagof o);
			raise "missing case";
		}

	Handle =>
		say("resp handle");
		pick o := op {
		Open or
		Opendir or
		Create =>
			f := fids.find(o.fid);
			if(f == nil)
				raise "no such fid?";
			f.fh = m.fh;
			f.mode = o.mode;
			qtype := Sys->QTFILE;
			if(tagof o == tagof Req.Opendir)
				qtype = Sys->QTDIR;
			qid := Sys->Qid (big pathgen++, 0, qtype);
			iounit := 32*1024;
			if(tagof o == tagof Req.Create)
				return (ref Rmsg.Create (op.m.tag, qid, iounit), nil);
			return (ref Rmsg.Open (op.m.tag, qid, iounit), nil);
		* =>
			(nil, sftpbuf) := cancelhandle(m.fh);
			(styxbuf, nil) := styxerror(op.m, "unexpected sftp handle message");
			return (styxbuf, sftpbuf);
		}

	Data =>
		say("resp data");
		pick o := op {
		Read =>	return (ref Rmsg.Read (op.m.tag, m.buf), nil);
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
			return (ref Rmsg.Read (op.m.tag, data), nil);
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
			return (ref Rmsg.Walk (op.m.tag, qids), nil);
		Stat =>
			say("op.stat");
			f := fids.find(o.sm.fid);
			say("attrs for op.stat, attrs "+m.attr.text());
			dir := m.attr.dir(str->splitstrr(f.path, "/").t1);
			return (ref Rmsg.Stat (o.m.tag, dir), nil);
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
dostyx(mm: ref Tmsg): (ref Rmsg, array of byte)
{
	say(sprint("dostyx, tag %d, %s", tagof mm, mm.text()));

	pick m := mm {
	Version =>
		# xxx should enforce this is the first message.
		if(m.tag != styx->NOTAG)
			return styxerror(m, "bad tag for version");
		if(m.version != "9P2000")
			return styxerror(m, "unknown");
		msize := min(32*1024, m.msize); # xxx sensible?
		say(sprint("using msize %d", msize));
		return (ref Rmsg.Version (m.tag, msize, "9P2000"), nil);

	Auth =>
		return styxerror(m, "no auth required");

	Attach =>
		f := fids.find(m.fid);
		if(f != nil)
			return styxerror(m, "fid already in use");
		f = ref Fid (m.fid, nil, 0, 1, "/", nil, nil);
		fids.add(m.fid, f);
		qid := Sys->Qid (big 0, 0, Sys->QTDIR);
		return (ref Rmsg.Attach (m.tag, qid), nil);

	Flush =>
		req := tabstyx.find(m.oldtag);
		if(req != nil) {
			tabstyx.del(m.oldtag);
			req.canceled = 1;
			# xxx cancel the action of the old styx message
		}
		return (ref Rmsg.Flush (m.tag), nil);

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
			return (ref Rmsg.Walk (m.tag, nil), nil);
		}
		npath := pathjoin(f.path, m.names);
		say(sprint("walk, npath %q", npath));

		return schedule(sftpstat(npath), ref Req.Walk (0, m, 0, npath, m));

	Open =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(m.mode & ~(3|Sys->OTRUNC))
			return styxerror(m, "mode not supported");
		if(f.fh != nil)
			return styxerror(m, "already open");

		if((m.mode&3) == 0 && (m.mode&Sys->OTRUNC))
			return styxerror(m, "cannot open for read-only & truncate");
		if((m.mode&3) && f.isdir)
			return styxerror(m, "directory cannot be opened for writing");

		nopens++;
		if(f.isdir)
			return schedule(sftpopendir(f.path), ref Req.Opendir (0, m, 0, m.fid, m.mode));
		pflags := mkpflags(m.mode, 0);
		return schedule(sftpopen(f.path, pflags), ref Req.Open (0, m, 0, m.fid, m.mode));

	Create =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(m.name == "." || m.name == "..")
			return styxerror(m, "cannot create . or ..");

		nopens++;
		npath := f.path+"/"+m.name;
		if(m.perm&Sys->DMDIR) {
			perms := m.perm & (~8r666 | (f.attr.perms&8r666));
			perms |= POSIX_S_IFDIR;
			return schedule(sftpmkdir(npath, perms), ref Req.Mkdir (0, m, 0, m.fid, m.mode, npath));
		}

		pflags := mkpflags(m.mode, 1);
		#perms := m.perm&8r777;
		perms := m.perm & (~8r777 | (f.attr.perms&8r777));
		return schedule(sftpcreate(npath, pflags, perms), ref Req.Create (0, m, 0, m.fid, m.mode));

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
				return (ref Rmsg.Read (m.tag, data), nil);
			}
			return schedule(sftpreaddir(f.fh), ref Req.Readdir (0, m, 0, m));
		} else {
			say(sprint("read, f.mode %o, Sys->OREAD %o", f.mode, Sys->OREAD));
			if(f.mode != Sys->OREAD && f.mode != Sys->ORDWR)
				return styxerror(m, "not open for reading");
			return schedule(sftpread(f.fh, m.offset, m.count), ref Req.Read (0, m, 0, m));
		}
		
	Write =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(f.fh == nil)
			return styxerror(m, "not open");
		say(sprint("write, f.mode %o, Sys->OWRITE %o", f.mode, Sys->OWRITE));
		if((f.mode&3) == 0)
			return styxerror(m, "not open for writing");
		return schedule(sftpwrite(f.fh, m.offset, m.data), ref Req.Write (0, m, 0, m, len m.data));

	Clunk =>
		say(sprint("clunk, fid %d", m.fid));
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		# xxx there might be an Open in transit!
		if(f.fh != nil)
			return schedule(sftpclose(f.fh), ref Req.Close (0, m, 0, m.fid));
		fids.del(m.fid);
		return (ref Rmsg.Clunk (m.tag), nil);

	Stat =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		return schedule(sftpstat(f.path), ref Req.Stat (0, m, 0, m));

	Remove => 
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		# xxx there might be an Open in transit!
		closebuf: array of byte;
		if(f.fh != nil) {
			# xxx should nopens-- when we saw the close
			(nil, closebuf) = schedule(sftpclose(f.fh), ref Req.Ignore (0, nil, 0));
		}

		sftpbuf: array of byte;
		if(f.isdir)
			(nil, sftpbuf) = schedule(sftprmdir(f.path), ref Req.Remove (0, m, 0, m));
		else
			(nil, sftpbuf) = schedule(sftpremove(f.path), ref Req.Remove (0, m, 0, m));
		if(closebuf != nil)
			sftpbuf = add(closebuf, sftpbuf);

		fids.del(m.fid); # xxx have to look at what happens when fid is still in use
		return (nil, sftpbuf);

	Wstat =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		flags := 0;
		vals := array[0] of ref Val;
		nd := sys->nulldir;
		d := m.stat;

		if(d.length != nd.length) {
			flags |= SSH_FILEXFER_ATTR_SIZE;
			vals = addval(vals, valbig(d.length));
		}
		if(d.uid != nd.uid) {
			flags |= SSH_FILEXFER_ATTR_UIDGID;
			vals = addval(vals, valstr(d.uid));
		}
		if(d.gid != nd.gid) {
			flags |= SSH_FILEXFER_ATTR_UIDGID;
			vals = addval(vals, valstr(d.gid));
		}
		if(d.mode != nd.mode) {
			if(f.isdir && !(d.mode&Sys->DMDIR) || !f.isdir && (d.mode&Sys->DMDIR))
				return styxerror(m, "cannot change directory bit");
			if((d.mode&~Sys->DMDIR)>>24)
				return styxerror(m, "can only set permissions, not other mode");
			perms := d.mode&8r777;
			if(f.isdir)
				perms |= POSIX_S_IFDIR;
			flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
			vals = addval(vals, valint(perms));
		}
		if(d.atime != nd.atime || d.mtime != nd.mtime) {
			flags |= SSH_FILEXFER_ATTR_ACMODTIME;
			vals = addval(vals, valint(d.atime));
			vals = addval(vals, valint(d.mtime));
		}
		return schedule(sftpsetstat(f.path, flags, vals), ref Req.Setstat1 (0, m, 0, m));
		#return schedule(sftpstat(f.path), ref Req.Setstat0 (0, m, 0, m));

	* =>
		raise "missing case";
	}
}

schedule(idbuf: (int, array of byte), req: ref Req): (ref Rmsg, array of byte)
{
	(id, buf) := idbuf;
	req.seq = id;
	tabsftp.add(req.seq, req);
	tabstyx.add(req.m.tag, req);
	return (nil, buf);
}

styxerror(m: ref Tmsg, s: string): (ref Rmsg, array of byte)
{
	return (ref Rmsg.Error(m.tag, s), nil);
}

add(a, b: array of byte): array of byte
{
	n := array[len a+len b] of byte;
	n[:] = a;
	n[len a:] = b;
	return n;
}

addval(vals: array of ref Val, v: ref Val): array of ref Val
{
	nv := array[len vals+1] of ref Val;
	nv[:] = vals;
	nv[len nv-1] = v;
	return nv;
}

mkpflags(mode, create: int): int
{
	f: int;
	case mode&3 {
	Sys->OREAD =>	f = SSH_FXF_READ;
	Sys->OWRITE =>	f = SSH_FXF_WRITE;
	Sys->ORDWR or
	Sys->ORDWR|Sys->OWRITE =>
		f = SSH_FXF_READ|SSH_FXF_WRITE;
	}
	if(mode&Sys->OTRUNC)
		f |= SSH_FXF_TRUNC|SSH_FXF_CREAT;

	if(create)
		f |= SSH_FXF_CREAT|SSH_FXF_EXCL;
	return f;
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
	say(sprint("sftppack, type %d %s, len buf %d", t, sftpnames[t], len buf));
	#say("sftp packet:");
	#hexdump(buf);
	return (id, buf);
}

sftpopendir(path: string): (int, array of byte)
{
	v := array[] of {valstr(path)};
	return sftppack(SSH_FXP_OPENDIR, v);
}

sftpopen(path: string, pflags: int): (int, array of byte)
{
	v := array[] of {
		valstr(path),
		valint(pflags),
		valint(0), # empty attrs
	};
	say(sprint("sfpopen, pflags: 0x%x", pflags));
	return sftppack(SSH_FXP_OPEN, v);
}

sftpcreate(path: string, pflags, perms: int): (int, array of byte)
{
	v := array[] of {
		valstr(path),
		valint(pflags),
		valint(SSH_FILEXFER_ATTR_PERMISSIONS),
		valint(perms),
	};
	say(sprint("sfpcreate, pflags: 0x%x", pflags));
	return sftppack(SSH_FXP_OPEN, v);
}

sftpmkdir(path: string, perms: int): (int, array of byte)
{
	v := array[] of {
		valstr(path),
		valint(SSH_FILEXFER_ATTR_PERMISSIONS),
		valint(perms),
	};
	return sftppack(SSH_FXP_MKDIR, v);
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

sftpwrite(fh: array of byte, off: big, data: array of byte): (int, array of byte)
{
	v := array[] of {valbytes(fh), valbig(off), valbytes(data)};
	return sftppack(SSH_FXP_WRITE, v);
}

sftpremove(path: string): (int, array of byte)
{
	v := array[] of {valstr(path)};
	return sftppack(SSH_FXP_REMOVE, v);
}

sftprmdir(path: string): (int, array of byte)
{
	v := array[] of {valstr(path)};
	return sftppack(SSH_FXP_RMDIR, v);
}

sftpstat(path: string): (int, array of byte)
{
	v := array[] of {valstr(path), valint(Statflags)};
	return sftppack(SSH_FXP_STAT, v);
}

sftpsetstat(path: string, flags: int, vals: array of ref Val): (int, array of byte)
{
	v := array[2+len vals] of ref Val;
	v[0] = valstr(path);
	v[1] = valint(flags);
	v[2:] = vals;
	return sftppack(SSH_FXP_SETSTAT, v);
}

sftprename(opath, npath: string): (int, array of byte)
{
	v := array[] of {valstr(opath), valstr(npath)};
	return sftppack(SSH_FXP_RENAME, v);
}

# xxx canonicalize paths locally



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

say(s: string)
{
	if(dflag)
		warn("sftp: "+s);
}

fail(s: string)
{
	warn(s);
	killgrp(pid());
	raise "fail:"+s;
}
