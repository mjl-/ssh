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
include "../lib/sshfmt.m";
include "../lib/sftp.m";
	sftp: Sftp;
	Attr, Tsftp, Rsftp: import sftp;
include "util0.m";
	util: Util0;
	hex, rev, min, pid, killgrp, warn, g32i: import util;

Sftpfs: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;
Dflag: int;

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


fids: ref Table[ref Fid];  # tmsg.fid
tabsftp: ref Table[ref Req];  # sftp seq
tabstyx: ref Table[ref Req];  # tmsg.tag
sftpgen := big 1;
pathgen := 0;
nopens:	int;

readstyxc,
styxwrotec,
readsftpc,
sftpwrotec:	chan of int;

styxreadc:	chan of ref Tmsg;
writestyxc:	chan of ref Rmsg;
sftpreadc:	chan of (ref Rsftp, string);
writesftpc:	chan of list of ref Tsftp;

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
	sftp = load Sftp Sftp->PATH;
	sftp->init();

	sys->pctl(Sys->NEWPGRP, nil);

	arg->init(args);
	arg->setusage(arg->progname()+" [-dD] [-s sshcmd | addr]");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
		'D' =>	Dflag++;
		's' =>	sshcmd = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args == 1 && sshcmd != nil || len args == 0 && sshcmd == nil)
		arg->usage();
	if(len args == 1)
		sshcmd = sprint("ssh -s %q sftp", hd args);

	readstyxc = chan of int;
	styxwrotec = chan of int;
	readsftpc = chan of int;
	sftpwrotec = chan of int;

	styxreadc = chan of ref Tmsg;
	writestyxc = chan of ref Rmsg;
	sftpreadc = chan of (ref Rsftp, string);
	writesftpc = chan of list of ref Tsftp;

	(tosftpfd, fromsftpfd) := run(sshcmd);

	initmsg := ref Tsftp.Init (big Sftp->Version, nil);
	if(sys->write(tosftpfd, buf := initmsg.pack(), len buf) != len buf)
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
		if(m != nil && Dflag)
			warn("<- "+m.text());
		sftpreadc <-= (m, err);
		if(m == nil || err != nil)
			break;
	}
}

sftpwriter(fd: ref Sys->FD)
{
	for(;;) {
		ml := <-writesftpc;
		for(; ml != nil; ml = tl ml) {
			m := hd ml;
			if(Dflag)
				warn("-> "+m.text());
			if(sys->write(fd, buf := m.pack(), len buf) != len buf)
				fail(sprint("sftp write: %r")); # xxx signal to main, for cleanup?
		}
		sftpwrotec <-= 0;
	}
}

styxwriting := 0;
sftpwriting := 0;
styxwaiting := 0;
sftpwaiting := 0;

handle(xm: ref Rmsg, sml: list of ref Tsftp)
{
	if(xm != nil) {
		if(styxwriting) {
			<-styxwrotec;
			styxwriting--;
		}
		writestyxc <-= xm;
		styxwriting++;
	}

	if(sml != nil) {
		if(sftpwriting) {
			<-sftpwrotec;
			sftpwriting--;
		}
		writesftpc <-= sml;
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
		(xm, sml) := dostyx(mm);
		handle(xm, sml);
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
		(xm, sml) := dosftp(m);
		handle(xm, sml);
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


cancelhandle(fh: array of byte): (ref Rmsg, list of ref Tsftp)
{
	return schedule(ref Tsftp.Close (big 0, fh), ref Req.Ignore (0, nil, 0));
}

dosftp(mm: ref Rsftp): (ref Rmsg, list of ref Tsftp)
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
		if(m.version != Sftp->Version)
			fail(sprint("remote has different sftp version %d, expected %d", m.version, Sftp->Version));

	Status =>
		say("resp status");

		pick o := op {
		Close =>
			nopens--;
			if(m.status != Sftp->SSH_FX_OK)
				warn("sftp close failed: "+m.errmsg);
			fids.del(o.fid);
			return (ref Rmsg.Clunk (op.m.tag), nil);
		Read or
		Readdir =>
			if(m.status == Sftp->SSH_FX_EOF)
				return (ref Rmsg.Read (op.m.tag, array[0] of byte), nil);
			return styxerror(op.m, "sftp read failed: "+m.errmsg); # should not happen
		Open or
		Opendir or
		Create =>
			nopens--;
			return styxerror(op.m, m.errmsg);
		Mkdir =>
			if(m.status != Sftp->SSH_FX_OK) {
				nopens--;
				return styxerror(op.m, m.errmsg);
			}
			return schedule(ref Tsftp.Opendir (big 0, o.path), ref Req.Opendir (0, o.m, 0, o.fid, o.mode));
		Stat =>
			return styxerror(op.m, m.errmsg);
		Walk =>
			return styxerror(op.m, m.errmsg);
		Write =>
			if(m.status != Sftp->SSH_FX_OK)
				return styxerror(op.m, "sftp write failed: "+m.errmsg);
			return (ref Rmsg.Write (op.m.tag, o.length), nil);
		Remove =>
			if(m.status != Sftp->SSH_FX_OK)
				return styxerror(op.m, "sftp remove failed: "+m.errmsg);
			return (ref Rmsg.Remove (op.m.tag), nil);
		Setstat1 =>
			if(m.status != Sftp->SSH_FX_OK)
				return styxerror(op.m, "sftp setstat attrs failed: "+m.errmsg);
			f := fids.find(o.wm.fid);
			if(f == nil)
				return styxerror(op.m, "setstat0: cannot find fid anymore");
			# xxx change/invalidate attr for all fids with the path?
			base := str->splitstrr(f.path, "/").t0;
			if(o.wm.stat.name == nil)
				return (ref Rmsg.Wstat (op.m.tag), nil);
			npath := base+"/"+o.wm.stat.name;
			return schedule(ref Tsftp.Rename (big 0, f.path, npath), ref Req.Setstat2 (0, o.m, 0, o.wm));
		Setstat2 =>
			if(m.status != Sftp->SSH_FX_OK)
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
				if(m.attrs[i].name != "." && m.attrs[i].name != "..") {
					dir := ref m.attrs[i].dir(nil);
					dir.qid.path = big pathgen++;
					dirs = dir::dirs;
				}
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
			dir.qid.path = big pathgen++;
			return (ref Rmsg.Stat (o.m.tag, dir), nil);
		* =>
			return styxerror(op.m, "unexpected sftp attrs message");
		}

	Extdata =>
		# xxx error instead?
		warn("remote sent unsolicited extdata, ignoring");
		return (nil, nil);

	* =>
		say("other reply?");
		raise "missing case";
	}
	return (nil, nil);
}

# returns either a styx response, or an sftp message
dostyx(mm: ref Tmsg): (ref Rmsg, list of ref Tsftp)
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

		return schedule(ref Tsftp.Stat (big 0, npath), ref Req.Walk (0, m, 0, npath, m));

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
			return schedule(ref Tsftp.Opendir (big 0, f.path), ref Req.Opendir (0, m, 0, m.fid, m.mode));
		pflags := mkpflags(m.mode, 0);
		return schedule(ref Tsftp.Open (big 0, f.path, pflags, nil), ref Req.Open (0, m, 0, m.fid, m.mode));

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
			perms |= Sftp->POSIX_S_IFDIR;
			attr := ref Attr;
			attr.flags = Sftp->SSH_FILEXFER_ATTR_PERMISSIONS;
			attr.perms = perms;
			return schedule(ref Tsftp.Mkdir (big 0, npath, attr), ref Req.Mkdir (0, m, 0, m.fid, m.mode, npath));
		}

		pflags := mkpflags(m.mode, 1);
		#perms := m.perm&8r777;
		perms := m.perm & (~8r777 | (f.attr.perms&8r777));
		attr := ref Attr;
		attr.flags = Sftp->SSH_FILEXFER_ATTR_PERMISSIONS;
		attr.perms = perms;
		return schedule(ref Tsftp.Open (big 0, npath, pflags, attr), ref Req.Create (0, m, 0, m.fid, m.mode));

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
			return schedule(ref Tsftp.Readdir (big 0, f.fh), ref Req.Readdir (0, m, 0, m));
		} else {
			say(sprint("read, f.mode %o, Sys->OREAD %o", f.mode, Sys->OREAD));
			if(f.mode != Sys->OREAD && f.mode != Sys->ORDWR)
				return styxerror(m, "not open for reading");
			return schedule(ref Tsftp.Read (big 0, f.fh, m.offset, m.count), ref Req.Read (0, m, 0, m));
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
		return schedule(ref Tsftp.Write (big 0, f.fh, m.offset, m.data), ref Req.Write (0, m, 0, m, len m.data));

	Clunk =>
		say(sprint("clunk, fid %d", m.fid));
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		# xxx there might be an Open in transit!
		if(f.fh != nil)
			return schedule(ref Tsftp.Close (big 0, f.fh), ref Req.Close (0, m, 0, m.fid));
		fids.del(m.fid);
		return (ref Rmsg.Clunk (m.tag), nil);

	Stat =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		return schedule(ref Tsftp.Stat (big 0, f.path), ref Req.Stat (0, m, 0, m));

	Remove => 
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		# xxx there might be an Open in transit!
		closemsg: ref Tsftp;
		if(f.fh != nil) {
			# xxx should nopens-- when we saw the close
			closemsg = ref Tsftp.Close (big 0, f.fh);
			(nil, nil) = schedule(closemsg, ref Req.Ignore (0, nil, 0));
		}

		ml: list of ref Tsftp;
		if(f.isdir)
			(nil, ml) = schedule(ref Tsftp.Rmdir (big 0, f.path), ref Req.Remove (0, m, 0, m));
		else
			(nil, ml) = schedule(ref Tsftp.Remove (big 0, f.path), ref Req.Remove (0, m, 0, m));
		if(closemsg != nil)
			ml = closemsg::ml;

		fids.del(m.fid); # xxx have to look at what happens when fid is still in use
		return (nil, ml);

	Wstat =>
		f := fids.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		nd := sys->nulldir;
		d := m.stat;

		a := ref Attr;
		a.flags = 0;

		if(d.length != nd.length) {
			a.flags |= Sftp->SSH_FILEXFER_ATTR_SIZE;
			a.size = d.length;
		}
		if(d.uid != nd.uid || d.gid != nd.gid) {
			a.flags |= Sftp->SSH_FILEXFER_ATTR_UIDGID;
			a.uid = int d.uid;
			a.gid = int d.uid;
		}
		if(d.mode != nd.mode) {
			if(f.isdir && !(d.mode&Sys->DMDIR) || !f.isdir && (d.mode&Sys->DMDIR))
				return styxerror(m, "cannot change directory bit");
			if((d.mode&~Sys->DMDIR)>>24)
				return styxerror(m, "can only set permissions, not other mode");
			perms := d.mode&8r777;
			if(f.isdir)
				perms |= Sftp->POSIX_S_IFDIR;
			a.flags |= Sftp->SSH_FILEXFER_ATTR_PERMISSIONS;
			a.perms = perms;
		}
		if(d.atime != nd.atime || d.mtime != nd.mtime) {
			a.flags |= Sftp->SSH_FILEXFER_ATTR_ACMODTIME;
			a.atime = d.atime;
			a.mtime = d.mtime;
		}
		return schedule(ref Tsftp.Setstat (big 0, f.path, a), ref Req.Setstat1 (0, m, 0, m));
		#return schedule(sftpstat(f.path), ref Req.Setstat0 (0, m, 0, m));

	* =>
		raise "missing case";
	}
}

schedule(m: ref Tsftp, req: ref Req): (ref Rmsg, list of ref Tsftp)
{
	m.id = sftpgen++;
	req.seq = int m.id;
	tabsftp.add(req.seq, req);
	tabstyx.add(req.m.tag, req);
	return (nil, m::nil);
}

styxerror(m: ref Tmsg, s: string): (ref Rmsg, list of ref Tsftp)
{
	return (ref Rmsg.Error(m.tag, s), nil);
}

mkpflags(mode, create: int): int
{
	f: int;
	case mode&3 {
	Sys->OREAD =>	f = Sftp->SSH_FXF_READ;
	Sys->OWRITE =>	f = Sftp->SSH_FXF_WRITE;
	Sys->ORDWR or
	Sys->ORDWR|Sys->OWRITE =>
		f = Sftp->SSH_FXF_READ|Sftp->SSH_FXF_WRITE;
	}
	if(mode&Sys->OTRUNC)
		f |= Sftp->SSH_FXF_TRUNC|Sftp->SSH_FXF_CREAT;

	if(create)
		f |= Sftp->SSH_FXF_CREAT|Sftp->SSH_FXF_EXCL;
	return f;
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

add(a, b: array of byte): array of byte
{
	n := array[len a+len b] of byte;
	n[:] = a;
	n[len a:] = b;
	return n;
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
