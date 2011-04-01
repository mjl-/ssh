# we begin by starting a styx reader & writer.
# we accept styx version & attach messages.
# only on later styx requests will we ensure there is a connection
# (i.e. make one if there isn't one).  when the connection is idle
# for some time, and no fids are open, we disconnect again.
#
# styx requests can be handled as follows:
# - immediate styx response
# - sftp request, sftp response, styx response
# some styx requests require multiple sftp requests, after each
# other or concurrent (where we only care for one response).
# in case of sftp request(s), we send the request and keep track of
# the original styx & sftp requests in tables (sftptab & styxtab).
# when the response comes in, we retrieve that information to
# interpret the response and either reply to the styx request or
# perform another stage for the styx request.
#
# tagtab maps tags to their styx requests, flushtab maps the tag
# they flush to the flush message.
# flushes are handled by responding to them immediately after
# responding to the original request, i.e. we always complete the
# original request.  this is easiest and makes sure we won't leave
# a multi-stage operation half-way in inconsistent state.  flushes
# of flushes are handled in the same way.
#
# we keep track of open files, fids.  they have a full path name
# which we can manipulate, e.g. add an element for a walk, or
# remove an element for a walk to "..".  we keep an sftp file
# handle with it, for open files.  we also cache whether the
# path is a directory or plain file.  this could lead to problems
# where a file on the sftp server is removed & recreated as
# different type (file/directory) without sftpfs knowing.
#
# we permanently remember qid.path's we assigned to opened plain files,
# not directories.  as long as we have a fid to a normal file (does not
# have to be open), we remember the qid.path too, but we forget when
# the last reference to the file goes away.
#
# when connected, we have 5 important threads:
# styxreader, styxwriter, sftpreader, sftpwriter, and main to
# coordinate them.  we only let styxreader read a next message
# when not currently writing to sftp.  this ensures main does not
# block on sending a message to sftpwriter while the remote sftp
# server is blocking on writing to us (but we won't receive from
# sftpreader).

implement Sftpfs;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "string.m";
	str: String;
include "sh.m";
	sh: Sh;
include "tables.m";
	tables: Tables;
	Strhash, Table: import tables;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import styx;
include "keyring.m";
include "../lib/sshfmt.m";
include "../lib/sftp.m";
	sftp: Sftp;
	Attr, Tsftp, Rsftp: import sftp;
include "util0.m";
	util: Util0;
	join, l2a, kill, hex, rev, min, pid, killgrp, warn, g32i: import util;

Sftpfs: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;
Dflag: int;
sflag: int;
sshcmd: string;
remotepath := ".";
connected: int;
sftpreadpid := -1;
sftpwritepid := -1;

Fid: adt {
	fid:	int;
	fh:	array of byte;  # file handle, nil == closed
	mode:	int;  # styx mode flags.  only valid when fh != nil
	isdir:	int;
	path:	string;
	dirs:	array of Sys->Dir;
	diroff:	big;
	qid:	Sys->Qid;

	text:	fn(f: self ref Fid): string;
};

fidtab: ref Table[ref Fid];  # tmsg.fid
sftptab: ref Table[ref Tsftp];  # tsftp seq -> Tsftp
styxtab: ref Table[ref Tmsg];  # tsftp seq -> Tmsg
tagtab: ref Table[ref Tmsg]; # tmsg.tag -> Tmsg, only for messages with sftp requests, not e.g. flushes
flushtab: ref Table[ref Tmsg.Flush]; # oldtag -> tmsg.flush
sftpgen := 1;
pathgen := 0;
laststyx: int;

Int: adt {
	v:	int;
};
qidtab:	ref Strhash[ref Int];

Path: adt {
	used,
	qid:	int;
};
filetab:	ref Strhash[ref Path];

Iounit:		con 32*1024;  # required by sftp
Styxmax:	con Styx->IOHDRSZ+Iounit;
idlesecs := 15*60;

sftpwriting,
styxreading:	int;
readstyxc:	chan of int;
sftpwrotec:	chan of string;
tickc:		chan of int;

styxreadc:	chan of ref Tmsg;
writestyxc:	chan of list of ref Rmsg;
sftpreadc:	chan of (ref Rsftp, string);
writesftpc:	chan of list of ref Tsftp;

Ebadfid:	con "no such fid";
Einuse:		con "fid already in use";
Eopen:		con "fid already open";
Enotopen:	con "fid not open";
Edot:		con ". and .. are illegal names";
Eaccess:	con "fid not open for mode";
Eclunked:	con "fid clunked";
Ebadsftp:	con "bad sftp reply";
Enotdir:	con "not a directory";
Enotfound:	con "file does not exist";
Eperm:		con "permission denied";

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
	arg->setusage(arg->progname()+" [-dD] [-i idlesecs] [-s sshcmd | addr] [remotepath]");
	while((ch := arg->opt()) != 0)
		case ch {
		'd' =>	dflag++;
		'D' =>	Dflag++;
		'i' =>	idlesecs = int arg->earg();
		's' =>	sflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args == 0)
		arg->usage();
	if(sflag)
		sshcmd = hd args;
	else
		sshcmd = sprint("ssh -s %q sftp", hd args);
	args = tl args;
	if(len args > 1)
		arg->usage();
	if(len args == 1)
		remotepath = hd args;

	readstyxc = chan of int;
	sftpwrotec = chan of string;
	tickc = chan of int;

	styxreadc = chan of ref Tmsg;
	writestyxc = chan of list of ref Rmsg;
	sftpreadc = chan of (ref Rsftp, string);
	writesftpc = chan of list of ref Tsftp;

	styxfd := sys->fildes(0);
	laststyx = sys->millisec();

	sftptab = sftptab.new(31, nil);
	fidtab = fidtab.new(31, nil);
	styxtab = styxtab.new(31, nil);
	tagtab = tagtab.new(31, nil);
	flushtab = flushtab.new(31, nil);

	qidtab = qidtab.new(101, nil);
	filetab = filetab.new(31, nil);

	spawn ticker();
	spawn styxreader(styxfd);
	spawn styxwriter(styxfd);
	styxreading = 1;
	readstyxc <-= 1;
	spawn main();
}

findqid(path: big, p: string): big
{
	qi := qidtab.find(p);
	if(qi != nil)
		return big qi.v;
	pf := filetab.find(p);
	if(pf != nil)
		return big pf.qid;
	return path;
}

fileincr(p: string): int
{
	f := filetab.find(p);
	if(f == nil) {
		f = ref Path (0, pathgen++);
		filetab.add(p, f);
	}
	f.used++;
	return f.qid;
}

filedecr(p: string)
{
	f := filetab.find(p);
	if(f == nil)
		raise "missing pathfid";
	if(--f.used == 0)
		filetab.del(p);
}

connect(): string
{
	(tosftpfd, fromsftpfd, err) := run(sshcmd);
	if(err != nil)
		return "run: "+err;

	initmsg := ref Tsftp.Init (Sftp->Version, nil);
	err = writemsg(tosftpfd, initmsg);
	if(err != nil)
		return "writing sftp initialisation message: "+err;

	rm: ref Rsftp;
	(rm, err) = readmsg(fromsftpfd);
	if(err != nil)
		return "reading sftp handshake response: "+err;
	pick m := rm {
	Version =>
		say(sprint("remote version is %d", m.id));
		if(m.id != Sftp->Version)
			return sprint("remote has different sftp version %d, expected %d", m.id, Sftp->Version);

	* =>
		return "expected 'Version' message, saw "+rm.text();
	}

	if(remotepath != "/") {
		tm := ref Tsftp.Realpath (sftpgen++, remotepath);
		writemsg(tosftpfd, tm);
		(rm, err) = readmsg(fromsftpfd);
		if(err != nil)
			return "reading realname response: "+err;
		if(rm.id != tm.id)
			return sprint("remote sent response with unexpected id %d, expected id %d", rm.id, tm.id);
		pick m := rm {
		Name =>
			if(len m.attrs != 1)
				return sprint("realname resonse did not have exactly 1 element, but %d", len m.attrs);
			remotepath = m.attrs[0].name;
			say(sprint("new remote path is %q", remotepath));

		Status =>
			return sprint("looking up remotepath %#q: %s", remotepath, m.errmsg);
		* =>
			return "unexpected response from remote, for realpath request: "+rm.text();
		}

		# fix remote path for attach points (which might have been created before sftp connection)
		for(i := 0; i < len fidtab.items; i++)
			for(l := fidtab.items[i]; l != nil; l = tl l) {
				(nil, f) := hd l;
				if(f.qid.path == big 0)
					f.path = remotepath;
			}
	}

	pidc := chan of int;
	spawn sftpreader(fromsftpfd, pidc);
	sftpreadpid = <-pidc;
	spawn sftpwriter(tosftpfd, pidc);
	sftpwritepid = <-pidc;
	connected = 1;
	return nil;
}

disconnect()
{
	kill(sftpreadpid);
	kill(sftpwritepid);
	sftpreadpid = sftpwritepid = -1;
	sftpwriting = 0;
	connected = 0;
}

run(cmd: string): (ref Sys->FD, ref Sys->FD, string)
{
	if(sys->pipe(tossh := array[2] of ref Sys->FD) != 0 || sys->pipe(fromssh := array[2] of ref Sys->FD) != 0)
		return (nil, nil, sprint("pipe: %r"));
	spawn run0(cmd, tossh[1], fromssh[0]);
	return (tossh[0], fromssh[1], nil);
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

ticker()
{
	for(;;) {
		sys->sleep(30*1000);
		tickc <-= 1;
	}
}

styxreader(fd: ref Sys->FD)
{
	for(;;) {
		<-readstyxc;
		styxreadc <-= m := Tmsg.read(fd, Styxmax);
		if(m == nil)
			break;
	}
}

styxwriter(fd: ref Sys->FD)
{
	for(;;) {
		ml := <-writestyxc;
		if(ml == nil)
			break;
		for(; ml != nil; ml = tl ml)
			if(sys->write(fd, buf := (hd ml).pack(), len buf) != len buf)
				fail(sprint("styx write: %r"));
	}
}

sftpreader(fd: ref sys->FD, pidc: chan of int)
{
	pidc <-= pid();
	for(;;) {
		(m, err) := readmsg(fd);
		sftpreadc <-= (m, err);
		if(m == nil || err != nil)
			break;
	}
}

sftpwriter(fd: ref Sys->FD, pidc: chan of int)
{
	pidc <-= pid();
	for(;;) {
		ml := <-writesftpc;
		for(; ml != nil; ml = tl ml) {
			err := writemsg(fd, hd ml);
			if(err != nil) {
				sftpwrotec <-= err;
				return;
			}
		}
		sftpwrotec <-= nil;
	}
}

readmsg(fd: ref Sys->FD): (ref Rsftp, string)
{
	(rm, err) := Rsftp.read(fd);
	if(rm != nil && Dflag)
		warn("<- "+rm.text());
	if(rm == nil && err == nil)
		err = "sftp eof";
	return (rm, err);
}

writemsg(fd: ref Sys->FD, tm: ref Tsftp): string
{
	if(Dflag)
		warn("-> "+tm.text());
	if(sys->write(fd, buf := tm.pack(), len buf) != len buf)
		return sprint("%r");
	return nil;
}

handle(xml: list of ref Rmsg, sml: list of ref Tsftp)
{
	if(xml != nil) {
		laststyx = sys->millisec();
		writestyxc <-= xml;
	}

	if(sml != nil) {
		if(sftpwriting) {
			err := <-sftpwrotec;
			if(err != nil)
				fail("sftp write: "+err);
			sftpwriting--;
		}
		writesftpc <-= sml;
		sftpwriting++;
	}
}

kick()
{
	if(!styxreading && !sftpwriting) {
		readstyxc <-= 1;
		styxreading++;
	}
}

main()
{
done:
	for(;;) alt {
	<-tickc =>
		msec := sys->millisec();
		if(connected && !sftpwriting && isempty(sftptab) && idlesecs > 0 && msec-laststyx > idlesecs*1000 && !needsftp()) {
			say("closing idle sftp connection");
			disconnect();
		}

	mm := <-styxreadc =>
		if(mm == nil)
			break done;
		pick m := mm {
		Readerror =>
			fail("styx read error: "+m.error);
		}

		laststyx = sys->millisec();
		styxreading--;
		(xm, sml) := dostyx(mm);
		if(xm != nil)
			xml := xm::nil;
		handle(xml, sml);
		kick();

	(m, err) := <-sftpreadc =>
		if(err != nil) {
			if(connected && idlesecs > 0 && !sftpwriting && isempty(sftptab) && !needsftp()) {
				warn("sftp read: "+err);
				disconnect();
				continue;
			}
			fail("sftp read: "+err);
		}

		(xml, sml) := dosftp(m);
		handle(xml, sml);

	err := <-sftpwrotec =>
		if(err != nil)
			fail("sftp write: "+err);
		sftpwriting--;
		kick();
	}
	say("main: done");
	killgrp(pid());
}


Fid.text(f: self ref Fid): string
{
	return sprint("Fid (fid %d, fh %d, mode %o, isdir %d, path %q, len dirs %d)", f.fid, f.fh != nil, f.mode, f.isdir, f.path, len f.dirs);
}


dostyx(mm: ref Tmsg): (ref Rmsg, list of ref Tsftp)
{
	if(dflag) say(sprint("dostyx, tag %d, %s", tagof mm, mm.text()));

	need := 1;
	case tagof mm {
	tagof Tmsg.Version or
	tagof Tmsg.Auth or
	tagof Tmsg.Attach or
	tagof Tmsg.Flush or
	tagof Tmsg.Clunk =>
		need = 0;
	}
	if(need && !connected) {
		err := connect();
		if(err != nil)
			return (ref Rmsg.Error (mm.tag, "no sftp connection: "+err), nil);
	}

	pick m := mm {
	Version =>
		if(m.tag != styx->NOTAG)
			return styxerror(m, "bad tag for version");
		(msize, version) := styx->compatible(m, Styxmax, "9P2000");
		say(sprint("using msize %d, version %#q", msize, version));

		fidtab = fidtab.new(31, nil);
		styxtab = styxtab.new(31, nil);
		tagtab = tagtab.new(31, nil);
		flushtab = flushtab.new(31, nil);

		return (ref Rmsg.Version (m.tag, msize, version), nil);

	Auth =>
		return styxerror(m, "no auth required");

	Attach =>
		f := fidtab.find(m.fid);
		if(f != nil)
			return styxerror(m, Einuse);
		# note: remotepath may be a relative path now.  this is fixed during connect()
		qid := Sys->Qid (big 0, 0, Sys->QTDIR);
		f = ref Fid (m.fid, nil, 0, 1, remotepath, nil, big 0, qid);
		fidtab.add(m.fid, f);
		return (ref Rmsg.Attach (m.tag, qid), nil);

	Flush =>
		if(tagtab.find(m.oldtag) == nil && flushtab.find(m.oldtag) == nil)
			return (ref Rmsg.Flush (m.tag), nil);
		flushtab.add(m.oldtag, m);

	Walk =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		if(f.fh != nil)
			return styxerror(m, Eopen);
		nf := fidtab.find(m.newfid);
		if(nf != nil && m.fid != m.newfid)
			return styxerror(m, Einuse);
		if(len m.names == 0) {
			nf = ref Fid (m.newfid, nil, 0, f.isdir, f.path, nil, big 0, f.qid);
			if(m.fid == m.newfid)
				fidtab.del(m.fid);
			fidtab.add(nf.fid, nf);
			if(m.fid != m.newfid && !nf.isdir)
				fileincr(nf.path);
			return (ref Rmsg.Walk (m.tag, nil), nil);
		}
		if(!f.isdir)
			return (ref Rmsg.Error (m.tag, Enotdir), nil);
		npath := pathjoin(f.path, m.names);
		if(dflag) say(sprint("walk, npath %q", npath));
		return schedule(m, ref Tsftp.Stat (0, npath));

	Open =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		if(f.fh != nil)
			return styxerror(m, Eopen);
		if(m.mode & ~(3|Sys->OTRUNC))
			return styxerror(m, "mode not supported");

		mode := m.mode & 3;
		write := mode == Styx->OWRITE || mode == Styx->ORDWR;
		if(write && f.isdir)
			return styxerror(m, "directory cannot be opened for writing");
		if(f.isdir && (m.mode & Sys->OTRUNC))
			return styxerror(m, "cannot truncate directory");

		if(f.isdir)
			return schedule(m, ref Tsftp.Opendir (0, f.path));

		pflags := mkpflags(m.mode, 0);
		return schedule(m, ref Tsftp.Open (0, f.path, pflags, nil));

	Create =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		if(f.fh != nil)
			return styxerror(m, Eopen);
		if(m.name == "." || m.name == "..")
			return styxerror(m, Edot);
		if(m.mode & ~(3|Sys->OTRUNC))
			return styxerror(m, "mode not supported");

		# fetch the directory attributes, to get permissions, for calculating new file's permissions
		return schedule(m, ref Tsftp.Stat (0, f.path));

	Read =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		if(f.fh == nil)
			return styxerror(m, Enotopen);

		case f.mode & 3 {
		Styx->OREAD or
		Styx->OEXEC or
		Styx->ORDWR =>
			;
		* =>
			return styxerror(m, Eaccess);
		}
		if(f.isdir) {
			if(m.offset == big 0) {
				f.dirs = nil;
				f.diroff = big 0;
			}
			if(m.offset != f.diroff)
				return styxerror(m, "bad directory offset");
			if(len f.dirs > 0)
				return (readdir(mm, f), nil);
			return schedule(m, ref Tsftp.Readdir (0, f.fh));
		} else {
			return schedule(m, ref Tsftp.Read (0, f.fh, m.offset, m.count));
		}
		
	Write =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		if(f.fh == nil)
			return styxerror(m, Enotopen);
		case f.mode & 3 {
		Styx->OWRITE or
		Styx->ORDWR =>
			;
		* =>
			return styxerror(m, Eaccess);
		}
		return schedule(m, ref Tsftp.Write (0, f.fh, m.offset, m.data));

	Clunk =>
		if(dflag) say(sprint("clunk, fid %d", m.fid));
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		if(f.fh != nil)
			return schedule(m, ref Tsftp.Close (0, f.fh));
		fidtab.del(m.fid);
		if(!f.isdir)
			filedecr(f.path);
		return (ref Rmsg.Clunk (m.tag), nil);

	Stat =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);
		return schedule(m, ref Tsftp.Stat (0, f.path));

	Remove => 
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);

		# we remove the fid now, so a possible open in transit will be closed again.
		# we do not care about the sftp response, so don't register a styx msg for it.
		closemsg: ref Tsftp;
		if(f.fh != nil) {
			closemsg = ref Tsftp.Close (0, f.fh);
			schedule(nil, closemsg);
		}

		if(f.isdir)
			(nil, ml) := schedule(m, ref Tsftp.Rmdir (0, f.path));
		else
			(nil, ml) = schedule(m, ref Tsftp.Remove (0, f.path));
		if(closemsg != nil)
			ml = closemsg::ml;

		if(!f.isdir)
			qidtab.del(f.path);
		fidtab.del(m.fid);
		if(!f.isdir)
			filedecr(f.path);
		return (nil, ml);

	Wstat =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, Ebadfid);

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

		if(a.flags == 0) {
			if(d.name == nd.name) {
				# sync, nothing to do for sftp
				return (ref Rmsg.Wstat (mm.tag), nil);
			}

			# just name, do it now
			base := str->splitstrr(f.path, "/").t0;
			npath := pathjoin(base, array[] of {d.name});
			return schedule(mm, ref Tsftp.Rename (0, f.path, npath));
		}
		# attrs first, name later
		return schedule(mm, ref Tsftp.Setstat (0, f.path, a));
	}
	raise "missing case";
}

readdir(mm: ref Tmsg, f: ref Fid): ref Rmsg
{
	rm: ref Tmsg.Read;
	pick m := mm {
	Read =>
		rm = m;
	* =>
		return ref Rmsg.Error (mm.tag, Ebadsftp);
	}
	size := 0;
	for(n := 0; n < len f.dirs; n++) {
		nd := styx->packdirsize(f.dirs[n]);
		if(size+nd > rm.count)
			break;
		size += nd;
	}
	if(n == 0)
		return ref Rmsg.Error(rm.tag, "single directory too small for read");
	data := array[size] of byte;
	o := 0;
	for(i := 0; i < n && i < len f.dirs; i++) {
		d := styx->packdir(f.dirs[i]);
		data[o:] = d;
		o += len d;
	}
	f.dirs = f.dirs[n:];
	f.diroff += big len data;
	return ref Rmsg.Read (rm.tag, data);
}


dosftp(mm: ref Rsftp): (list of ref Rmsg, list of ref Tsftp)
{
	tsm := sftptab.find(mm.id);
	txm := styxtab.find(mm.id);
	sftptab.del(mm.id);
	styxtab.del(mm.id);
	if(txm != nil)
		tagtab.del(txm.tag);

	if(tsm == nil)
		fail("sftp server sent unsolicited reply: "+mm.text());

	if(dflag) {
		say("dosftp:");
		if(txm == nil)
			say("	tmsg: nil");
		else
			say("	tmsg: "+txm.text());
		say("	tsftp: "+tsm.text());
		say("	rsftp: "+mm.text());
	}

	# styx requests may have been cancelled (e.g. due to Tmsg.Version),
	# undo the effect of the sftp request.
	if(txm == nil) {
		pick m := mm {
		Handle =>
			(nil, sftpml) := schedule(nil, ref Tsftp.Close (0, m.fh));
			return (nil, sftpml);
		}
		return (nil, nil);
	}

	noflush := 0;
	rm: ref Rmsg;
	sftpml: list of ref Tsftp;
styx:
	pick tm := txm {
	Walk =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}
		pick m := mm {
		Attrs =>
			if((m.attr.flags & Sftp->SSH_FILEXFER_ATTR_PERMISSIONS) == 0) {
				rm = ref Rmsg.Error (tm.tag, "sftp stat response has no permissions field");
				break styx;
			}
			isdir := (m.attr.perms & Sftp->POSIX_S_IFDIR) != 0;
			path: string;
			pick tt := tsm {
			Stat =>
				path = tt.path;
			* =>
				rm = ref Rmsg.Error (tm.tag, Ebadsftp);
				break styx;
			}
			qid: Sys->Qid;
			nf := ref Fid (tm.newfid, nil, 0, isdir, path, nil, big 0, qid);
			if(tm.fid == tm.newfid)
				fidtab.del(tm.fid);
			fidtab.add(nf.fid, nf);
			if(!nf.isdir)
				fileincr(nf.path);
			if(!f.isdir && tm.fid == tm.newfid)
				filedecr(f.path);
			qids := array[len tm.names] of Sys->Qid;
			for(i := 0; i < len tm.names-1; i++)
				qids[i] = Sys->Qid (big pathgen++, 0, Sys->QTDIR);
			qids[i] = Sys->Qid (big pathgen++, 0, Sys->QTFILE);
			if(isdir)
				qids[i].qtype = Sys->QTDIR;
			else
				qids[i].path = findqid(qids[i].path, pathjoin(f.path, tm.names));
			nf.qid = qids[i];
			rm = ref Rmsg.Walk (tm.tag, qids);
		* =>
			rm = rerror(tm.tag, mm);
		}

	Open =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}
		pick m := mm {
		Handle =>
			if(f.fh != nil) {
				rm = ref Rmsg.Error (tm.tag, Eopen);
				(nil, sftpml) = schedule(nil, ref Tsftp.Close (0, f.fh));
				break styx;
			}
			f.fh = m.fh;
			f.mode = tm.mode;
			f.qid.qtype = Sys->QTFILE;
			if(tagof tsm == tagof Tsftp.Opendir)
				f.qid.qtype = Sys->QTDIR;

			if(!f.isdir && qidtab.find(f.path) == nil)
				qidtab.add(f.path, ref Int (int f.qid.path));
			rm = ref Rmsg.Open (tm.tag, f.qid, Iounit);
		* =>
			rm = rerror(tm.tag, mm);
		}

	Create =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}

		if(tagof tsm == tagof Tsftp.Stat) {
			perm: int;
			pick m := mm {
			Attrs =>
				if((m.attr.flags & Sftp->SSH_FILEXFER_ATTR_PERMISSIONS) == 0) {
					rm = ref Rmsg.Error (tm.tag, "cannot determine permissions for directory");
					break styx;
				}
				perm = m.attr.perms;
			* =>
				rm = rerror(tm.tag, mm);
				break styx;
			}

			attr := ref Attr;
			attr.flags = Sftp->SSH_FILEXFER_ATTR_PERMISSIONS;

			npath := pathjoin(f.path, array[] of {tm.name});
			if(tm.perm&Sys->DMDIR) {
				attr.perms = tm.perm & (~8r777 | (perm&8r777));
				(nil, sftpml) = schedule(tm, ref Tsftp.Mkdir (0, npath, attr));
				noflush = 1;
			} else {
				pflags := mkpflags(tm.mode, 1);
				attr.perms = tm.perm & (~8r666 | (perm&8r666));
				(nil, sftpml) = schedule(tm, ref Tsftp.Open (0, npath, pflags, attr));
				noflush = 1;
			}

		} else if(tagof tsm == tagof Tsftp.Mkdir) {
			pick m := mm {
			Status =>
				if(m.status == Sftp->SSH_FX_OK) {
					# qid.qtype is already set to QTDIR
					(nil, sftpml) = schedule(tm, ref Tsftp.Opendir (0, pathjoin(f.path, array[] of {tm.name})));
					noflush = 1;
					break styx;
				}
			}
			rm = rerror(tm.tag, mm);
		} else {
			# we get here both for the Tsftp.Create from dostyx and for Tsftp.Opendir from above

			if(f.fh != nil) {
				# this could happen if client sends two consecutive creates.  undo.
				pick m := mm {
				Handle =>
					(nil, sftpml) = schedule(nil, ref Tsftp.Close (0, m.fh));
				}
				rm = ref Rmsg.Error (tm.tag, Eopen);
				break styx;
			}
			pick m := mm {
			Handle =>
				f.fh = m.fh;
				f.mode = tm.mode;
				f.isdir = (tm.mode & Sys->DMDIR) != 0;
				f.path = pathjoin(f.path, array[] of {tm.name});
				f.qid.qtype = Sys->QTFILE;
				if(f.isdir)
					f.qid.qtype = Sys->QTDIR;
				filetab.del(f.path);  # probably none
				qidtab.del(f.path);  # probably none
				if(!f.isdir) {
					f.qid.path = big fileincr(f.path);
					qidtab.add(f.path, ref Int (int f.qid.path));
				} else
					f.qid.path = big pathgen++;
				rm = ref Rmsg.Create (tm.tag, f.qid, Iounit);
			}
		}

	Read =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}
		if(tagof tsm == tagof Tsftp.Readdir) {
			pick m := mm {
			Name =>
				f.dirs = array[len m.attrs] of Sys->Dir;
				n := 0;
				err: string;
				for(i := 0; i < len m.attrs; i++) {
					if(m.attrs[i].name == "." || m.attrs[i].name == "..")
						continue;
					(f.dirs[n], err) = m.attrs[i].dir(big pathgen++, nil);
					f.dirs[n].qid.path = findqid(f.dirs[n].qid.path, f.path+"/"+f.dirs[n].name);
					n++;
					if(err != nil) {
						rm = ref Rmsg.Error (tm.tag, err);
						break styx;
					}
				}
				f.dirs = f.dirs[:n];
				if(len f.dirs == 0)
					rm = ref Rmsg.Read (tm.tag, array[0] of byte);
				else
					rm = readdir(tm, f);
			Status =>
				if(m.status == Sftp->SSH_FX_EOF)
					rm = ref Rmsg.Read (tm.tag, array[0] of byte);
			}
			if(rm == nil)
				rm = rerror(tm.tag, mm);
		} else {
			pick m := mm {
			Data =>
				rm = ref Rmsg.Read (tm.tag, m.buf);
			Status =>
				if(m.status == Sftp->SSH_FX_EOF)
					rm = ref Rmsg.Read (tm.tag, array[0] of byte);
			}
			if(rm == nil)
				rm = rerror(tm.tag, mm);
		}

	Write =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}

		rm = ref Rmsg.Write (tm.tag, len tm.data);
		err := statusok(mm);
		if(err != nil)
			rm = ref Rmsg.Error (tm.tag, err);

	Clunk =>
		f := fidtab.find(tm.fid);
		fidtab.del(tm.fid);
		if(f != nil && !f.isdir)
			filedecr(f.path);
		rm = ref Rmsg.Clunk (tm.tag);

	Stat =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}
		pick m := mm {
		Attrs =>
			name := str->splitstrr(f.path, "/").t1;
			(dir, err) := m.attr.dir(f.qid.path, name);
			if(err != nil)
				rm = ref Rmsg.Error (tm.tag, err);
			else
				rm = ref Rmsg.Stat (tm.tag, dir);
		}
		if(rm == nil)
			rm = rerror(tm.tag, mm);

	Remove =>
		# note: fid is gone already
		rm = ref Rmsg.Remove (tm.tag);
		err := statusok(mm);
		if(err != nil)
			rm = ref Rmsg.Error (tm.tag, err);

	Wstat =>
		f := fidtab.find(tm.fid);
		if(f == nil) {
			rm = ref Rmsg.Error (tm.tag, Eclunked);
			break styx;
		}
		pick t := tsm {
		Rename =>
			rm = ref Rmsg.Wstat (tm.tag);
			err := statusok(mm);
			if(err != nil)
				rm = ref Rmsg.Error (tm.tag, err);

		Setstat =>
			pick m := mm {
			Status =>
				if(m.status != Sftp->SSH_FX_OK) {
					rm = rerror(tm.tag, mm);
					break styx;
				}

				if(tm.stat.name == (Sys->nulldir).name) {
					rm = ref Rmsg.Wstat (tm.tag);
					break styx;
				}

				base := str->splitstrr(f.path, "/").t0;
				npath := pathjoin(base, array[] of {tm.stat.name});
				(nil, sftpml) = schedule(tm, ref Tsftp.Rename (0, f.path, npath));
				noflush = 1;
			* =>
				rm = ref Rmsg.Error (tm.tag, Ebadsftp);
			}
		}

	* =>
		raise "scheduled sftp msg for other styx message?";
	}

	if(rm != nil)
		ml := rm::nil;
	if(!noflush) {
		tag := txm.tag;
		for(;;) {
			fm := flushtab.find(tag);
			if(fm == nil)
				break;
			flushtab.del(tag);
			ml = ref Rmsg.Flush (fm.tag)::ml;
			tag = fm.tag;
		}
	}

	return (rev(ml), sftpml);
}

sftperror(status: int, errmsg: string): string
{
	case status {
        Sftp->SSH_FX_NO_SUCH_FILE =>
		errmsg = Enotfound;
        Sftp->SSH_FX_PERMISSION_DENIED =>
		errmsg = Eperm;
	* =>
		errmsg = str->tolower(errmsg);
	}
	return errmsg;
}

rerror(tag: int, mm: ref Rsftp): ref Rmsg.Error
{
	pick m := mm {
	Status =>
		return ref Rmsg.Error (tag, sftperror(m.status, m.errmsg));
	}
	return ref Rmsg.Error (tag, Ebadsftp);
}

statusok(mm: ref Rsftp): string
{
	pick m := mm {
	Status =>
		if(m.status ==  Sftp->SSH_FX_OK)
			return nil;
		return sftperror(m.status, m.errmsg);
	* =>
		return Ebadsftp;
	}
}

schedule(xm: ref Tmsg, m: ref Tsftp): (ref Rmsg, list of ref Tsftp)
{
	m.id = sftpgen++;
	sftptab.add(m.id, m);
	if(xm != nil) {
		styxtab.add(m.id, xm);
		tagtab.add(xm.tag, xm);
	}
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
	Styx->OREAD or
	Styx->OEXEC =>	f = Sftp->SSH_FXF_READ;
	Styx->OWRITE =>	f = Sftp->SSH_FXF_WRITE;
	Styx->ORDWR =>	f = Sftp->SSH_FXF_READ|Sftp->SSH_FXF_WRITE;
	}
	if(mode&Styx->OTRUNC)
		f |= Sftp->SSH_FXF_TRUNC|Sftp->SSH_FXF_CREAT;
	if(create)
		f |= Sftp->SSH_FXF_CREAT|Sftp->SSH_FXF_EXCL;
	return f;
}

# might want to do this using sftp realpath.  for non-unix servers.  will make it all slower.
pathjoin(base: string, a: array of string): string
{
	if(base != nil && base[0] != '/')
		raise "path not absolute";

	ab := sys->tokenize(base, "/").t1;
	na := array[len ab+len a] of string;
	na[:] = l2a(ab);
	na[len ab:] = a;

	l: list of string;
	for(i := 0; i < len na; i++)
		case na[i] {
		"." =>
			;
		".." =>
			if(l != nil)
				l = tl l;
		* =>
			l = na[i]::l;
		}

	return "/"+join(rev(l), "/");
}

# we need an sftp connection if we have open fids
needsftp(): int
{
	for(i := 0; i < len fidtab.items; i++)
		for(l := fidtab.items[i]; l != nil; l = tl l) {
			(nil, f) := hd l;
			if(f.fh != nil)
				return 1;
		}
	return 0;
}

isempty[T](r: ref Table[T]): int
{
	for(i := 0; i < len r.items; i++)
		if(r.items[i] != nil)
			return 0;
	return 1;
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
