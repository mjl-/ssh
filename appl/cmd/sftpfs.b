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
	hex, hexfp: import sshlib;
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

# operation
Op: adt {
	seq:	int; # sftp sequence number
	m:	ref Tmsg; # styx tmsg
	pick {
	Walk =>
		npath:	string;
		wm:	ref Tmsg.Walk;
	Open or Opendir =>
		fid, mode:	int;
	Stat =>
		sm:	ref Tmsg.Stat;
	Readdir or Read or Close =>
	}
};

fids: ref Table[ref Fid];  # tmsg.fid
operations: ref Table[ref Op];  # sftp seq
requests: ref Table[ref Tmsg];  # tmsg.tag
sftpgen := 1;
pathgen := 0;
sshc: ref Sshc;


Attr: adt {
	flags:	int;
	size:	big;
	owner, group:	string;
	perms:	int;
	atime, mtime:	int;
	vals:	array of ref Val;

	mk:	fn(a: array of ref Val): ref Attr;
	isdir:	fn(a: self ref Attr): int;
	dir:	fn(a: self ref Attr, name: string): Sys->Dir;
	text:	fn(a: self ref Attr): string;
};

statflags := SSH_FILEXFER_ATTR_SIZE|SSH_FILEXFER_ATTR_UIDGID|SSH_FILEXFER_ATTR_PERMISSIONS|SSH_FILEXFER_ATTR_ACMODTIME;

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
	arg->setusage(arg->progname()+" [-dD] [-e enc-algs] [-m mac-algs] [-k keyspec] addr");
	while((ch := arg->opt()) != 0)
		case ch {
		'D' =>	Dflag++;
		'd' =>	dflag++;
			sshlib->dflag = max(0, dflag-1);
		'e' or 'm' =>
			t := sshlib->Aenc;
			if(ch == 'm')
				t = sshlib->Amac;
			(names, err) := sshlib->parsenames(arg->earg());
			if(err == nil)
				err = cfg.set(t, names);
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
	operations = operations.new(32, nil);
	requests = requests.new(32, nil);

	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", addr));
	(c, lerr) := Sshc.login(conn.dfd, addr, keyspec, Cfg.default());
	if(lerr != nil)
		fail(lerr);
	say("logged in");
	sshc = c;

	# byte      SSH_MSG_CHANNEL_OPEN
	# string    channel type in US-ASCII only
	# uint32    sender channel
	# uint32    initial window size
	# uint32    maximum packet size
	# ....      channel type specific data follows
	vals := array[] of {
		valstr("session"),
		valint(0),
		valint(1*1024*1024),
		valint(32*1024),
	};
	ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_OPEN, vals);

	time0 = daytime->now();

	spawn sshreader(c);
	spawn styxreader(sys->fildes(0), msgc);
	spawn main(msgc, c);
}

main(msgc: chan of ref Tmsg, c: ref Sshc)
{
	a: array of ref Val;

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
			say("msg ignore, data: "+getstr(a[0]));

			a = array[] of {valstr("test!")};
			ewritepacket(c, Sshlib->SSH_MSG_IGNORE, a);

		Sshlib->SSH_MSG_DEBUG =>
			cmd("### msg debug");
			# byte      SSH_MSG_DEBUG
			# boolean   always_display
			# string    message in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			a = eparsepacket(d[1:], list of {Tbool, Tstr, Tstr});
			say("remote debug: "+getstr(a[1]));

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

			say("writing 'subsystem' channel request");
			# byte      SSH_MSG_CHANNEL_REQUEST
			# uint32    recipient channel
			# string    "subsystem"
			# boolean   want reply
			# string    subsystem name
			vals := array[] of {
				valint(0),
				valstr("subsystem"),
				valbool(1),
				valstr("sftp"),
			};
			ewritepacket(c, Sshlib->SSH_MSG_CHANNEL_REQUEST, vals);
			say("wrote request to execute command");

		Sshlib->SSH_MSG_CHANNEL_SUCCESS =>
			cmd("### channel success");
			eparsepacket(d[1:], list of {Tint});

			vals := array[] of {
				valbyte(byte SSH_FXP_INIT),
				valint(3),
			};
			buf := packpacket(vals);
			vals = array[] of {
				valint(0),
				valbytes(buf),
			};
			ewritepacket(sshc, Sshlib->SSH_MSG_CHANNEL_DATA, vals);

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
			buf := getbytes(a[1]);
			if(sys->write(sys->fildes(1), buf, len buf) != len buf)
				fail(sprint("write: %r"));

			# xxx assuming one sftp packet per data-message.  bogus.
			dosftp(buf);

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
				buf := getbytes(a[2]);
				if(sys->write(sys->fildes(2), buf, len buf) != len buf)
					fail(sprint("write: %r"));
			* =>
				warn("extended data but not stderr?");
				warn(getstr(a[2]));
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
			return;

		Sshlib->SSH_MSG_CHANNEL_OPEN_FAILURE =>
			cmd("### channel open failure");
			# byte      SSH_MSG_CHANNEL_OPEN_FAILURE
			# uint32    recipient channel
			# uint32    reason code
			# string    description in ISO-10646 UTF-8 encoding [RFC3629]
			# string    language tag [RFC3066]
			a = eparsepacket(d[1:], list of {Tint, Tint, Tstr, Tstr});
			fail("channel open failure: "+getstr(a[2]));

		Sshlib->SSH_MSG_CHANNEL_WINDOW_ADJUST =>
			cmd("### channel window adjust");
			# byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
			# uint32    recipient channel
			# uint32    bytes to add
			a = eparsepacket(d[1:], list of {Tint, Tint});
		* =>
			cmd(sprint("### other packet type %d", int d[0]));
		}
	}
	killgrp(sys->pctl(0, nil));
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

Attr.mk(a: array of ref Val): ref Attr
{
	#(absent)stat[0] = string .
	#(absent)stat[1] = string drwxr-xr-x   15 root     wheel         512 Sep 19 23:53 .
	#stat[2] = 15
	#stat[3] = 512
	#stat[4] = 0
	#stat[5] = 0
	#stat[6] = 16877
	#stat[7] = 1217787098
	#stat[8] = 1221861185
	flags := getint(a[0]);
	size := getbig(a[1]);
	uid := string getint(a[2]);
	gid := string getint(a[3]);
	perms := getint(a[4]);
	atime := getint(a[5]);
	mtime := getint(a[6]);
	attr := ref Attr (flags, size, uid, gid, perms, atime, mtime, a);
	return attr;
}

Attr.text(a: self ref Attr): string
{
	return sprint("Attr (size %bd, uid/gid %q %q mode %o isdir %d atime %d mtime %d", a.size, a.owner, a.group, a.perms&8r777, a.isdir(), a.atime, a.mtime);
}

dosftp(d: array of byte)
{
	# fields in attrs
	lattrs := list of {Tint, Tbig, Tint, Tint, Tint, Tint, Tint};

	say(sprint("dosftp, len d %d, buf:", len d));
	sshlib->hexdump(d);

	hdrsize := 4+1+4;
	if(len d < hdrsize)
		fail("short sftp message");
	msg := eparsepacket(d[:hdrsize], list of {Tint, Tbyte, Tint});

	length := getint(msg[0]);
	if(len d-4 != length)
		fail(sprint("malsized message, expect %d, have %d", length, len d-4));
	t := int getbyte(msg[1]);
	id := getint(msg[2]);
	say(sprint("sftp msg, length %d, t %d, id %d", length, t, id));

	op := operations.find(id);
	if(op != nil) {
		operations.del(id);
		requests.del(op.m.tag);
	} else
		warn(sprint("id %d not registered?", id));

	body := d[hdrsize:];
	case t {
	SSH_FXP_VERSION =>
		say("resp version");
		version := id;
		say(sprint("remote version is %d", version));

	SSH_FXP_STATUS =>
		# uint32     error/status code
		# string     error message (ISO-10646 UTF-8 [RFC-2279])
		# string     language tag (as defined in [RFC-1766])
		say("resp status");
		a := eparsepacket(body, list of {Tint, Tstr, Tstr});
		status := getint(a[0]);
		case status {
		SSH_FX_OK =>
			# for remove?  write?  setstat?  etc...
			pick o := op {
			Close =>
				pick clunkmsg := op.m {
				Clunk =>	fids.del(clunkmsg.fid);
				* =>	fail("unexpected");
				}
				return reply(ref Rmsg.Clunk (op.m.tag));
			* =>
				fail("unexpected");
			}
			say("ok ?");
			;
		SSH_FX_EOF =>
			say("eof");
			# for read, readdir
			pick o := op {
			Read or Readdir =>
				return reply(ref Rmsg.Read(op.m.tag, array[0] of byte));
			* =>
				fail("unexpected");
			}
		* =>
			say("other");
			errmsg := getstr(a[1]);
			say(sprint("sftp error %s", errmsg));
			return replyerror(op.m, errmsg);
		}

	SSH_FXP_HANDLE =>
		say("resp handle");
		a := eparsepacket(body, list of {Tstr});
		fh := getbytes(a[0]);
		pick o := op {
		Open or Opendir =>
			f := fids.find(o.fid);
			if(f == nil)
				raise "no such fid?";
			f.fh = fh;
			f.mode = o.mode;
			qtype := Sys->QTFILE;
			if(tagof o == tagof Op.Opendir)
				qtype = Sys->QTDIR;
			qid := Sys->Qid (big pathgen++, 0, qtype);
			iounit := 1024; # xxx
			return reply(ref Rmsg.Open (op.m.tag, qid, iounit));
		* =>
			raise "unexpected handle";
		}

	SSH_FXP_DATA =>
		say("resp data");
		# from ead
		a := eparsepacket(body, list of {Tstr});
		buf := getbytes(a[0]);

		pick o := op {
		Read =>	return reply(ref Rmsg.Read (op.m.tag, buf));
		* =>	fail("unexpected 'data'");
		}

	SSH_FXP_NAME =>
		say("resp name");
		# from readdir
		#uint32     id
		#uint32     count
		#repeats count times:
		#	string     filename
		#	string     longname
		#	ATTRS      attrs
		a := eparsepacket(body[:4], list of {Tint});
		count := getint(a[0]);
		say(sprint("names has %d entries", count));

		multiattrs: list of int;
		for(i := 0; i < count; i++)
			multiattrs = Tstr::Tstr::Tint::Tbig::Tint::Tint::Tint::Tint::Tint::multiattrs;
		stat := eparsepacket(body[4:], multiattrs);
		for(i = 0; i < len stat; i++)
			say(sprint("stat[%d] = %s", i, stat[i].text()));
		o := 0;
		dirs: list of ref Sys->Dir;
		f: ref Fid;
		rm: ref Tmsg.Read;
		pick omsg := op.m {
		Read =>	rm = omsg;
		* =>	raise "bogus Tmsg";
		}
		f = fids.find(rm.fid);
		while(o < len stat) {
			say(sprint("stat, o %d, total %d", o, len stat));
			filename := getstr(stat[o]);
			attr := Attr.mk(stat[o+2:o+2+len lattrs]);
			say(sprint("have attr, filename %s, attr %s", filename, attr.text()));
			dirs = ref attr.dir(filename)::dirs;
			o += 2+len lattrs;
		}
		f.dirs = dirs;

		data := array[0] of byte;
		while(f.dirs != nil) {
			buf := styx->packdir(*hd f.dirs);
			if(len data+len buf <= rm.count) {
				data = add(data, buf);
				f.dirs = tl f.dirs;
			}
		}
		return reply(ref Rmsg.Read (op.m.tag, data));

	SSH_FXP_ATTRS =>
		say("resp attrs");
		# uint32   flags
		# uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
		# uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
		# uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
		# uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
		# uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
		# uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
		# uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
		# string   extended_type
		# string   extended_data
		# ...      more extended data (extended_type - extended_data pairs),
		# 	   so that number of pairs equals extended_count

		a := eparsepacket(body, lattrs);
		
		attr := Attr.mk(a);
		say("have stat: "+attr.text());

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
			isdir := attr.isdir();
			nf := ref Fid (o.wm.newfid, nil, 0, isdir, o.npath, nil, attr);
			fids.add(o.wm.newfid, nf);
			say("op.walk done, fid "+nf.text());
			return reply(ref Rmsg.Walk (op.m.tag, qids));
		Stat =>
			say("op.stat");
			f := fids.find(o.sm.fid);
			dir := attr.dir(str->splitstrr(f.path, "/").t1);
			return reply(ref Rmsg.Stat (o.m.tag, dir));
		}

	SSH_FXP_EXTENDED =>
		say("extended");
		fail("unexpected");

	SSH_FXP_EXTENDED_REPLY =>
		say("extended reply");
		fail("unexpected");
	* =>
		say("other reply?");
		fail("unexpected");
	}
}

eparsepacket(d: array of byte, l: list of int): array of ref Val
{
	(a, err) := sshlib->parsepacket(d, l);
	if(err != nil)
		fail(err);
	return a;
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
		msize := min(8*1024, m.msize);
		say(sprint("using msize %d", msize));
		om = ref Rmsg.Version (m.tag, msize, "9P2000");
	Auth =>
		replyerror(m, "no auth required");
	Attach =>
		# xxx check if fid isn't in use already
		f := fids.find(m.fid);
		if(f != nil)
			return replyerror(m, "fid already in use");
		# xxx stat /?
		f = ref Fid (m.fid, nil, 0, 1, "/", nil, nil);
		fids.add(m.fid, f);
		qid := Sys->Qid (big 0, 0, Sys->QTDIR);
		om = ref Rmsg.Attach (m.tag, qid);

	Flush =>
		# xxx find Tmsg in requests
		#oldtag: int;
		# xxx implement
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

		seq := sftpstat(npath);
		op := ref Op.Walk (seq, m, npath, m);
		operations.add(seq, op);
		requests.add(m.tag, m);
		return;

	Open =>
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		if(m.mode & ~(Sys->OREAD|Sys->OWRITE))
			return replyerror(m, "mode not supported");
		if(f.fh != nil)
			return replyerror(m, "already open");

		if(f.isdir) {
			seq := sftpopendir(f.path);
			op := ref Op.Opendir (seq, m, m.fid, m.mode);
			operations.add(seq, op);
			requests.add(m.tag, m);
		} else {
			seq := sftpopen(f.path, m.mode, f.attr);
			op := ref Op.Open (seq, m, m.fid, m.mode);
			operations.add(seq, op);
			requests.add(m.tag, m);
		}

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
			seq := sftpreaddir(f.fh);
			op := ref Op.Readdir (seq, m);
			operations.add(seq, op);
			requests.add(m.tag, m);
		} else {
			say(sprint("read, f.mode %o, Sys->OREAD %o", f.mode, Sys->OREAD));
			if(f.mode != Sys->OREAD && f.mode != Sys->ORDWR)
				return replyerror(m, "not open for reading");
			seq := sftpread(f.fh, m.offset, m.count);
			op := ref Op.Read (seq, m);
			operations.add(seq, op);
			requests.add(m.tag, m);
		}
		return;
		
	Write =>
		# just write
		#fid: int;
		#offset: big;
		#data: array of byte;
		return replyerror(m, "read-only for now");
	Clunk =>
		# if open, close handle
		# forget about fid
		#fid: int;
		say(sprint("clunk, fid %d", m.fid));
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		if(f.fh != nil) {
			seq := sftpclose(f.fh);
			op := ref Op.Close (seq, m);
			operations.add(seq, op);
		} else
			om = ref Rmsg.Clunk (m.tag);
	Stat =>
		# stat (with following link)
		#fid: int;
		f := fids.find(m.fid);
		if(f == nil)
			return replyerror(m, "no such fid");
		seq := sftpstat(f.path);
		op := ref Op.Stat (seq, m, m);
		operations.add(seq, op);
		return;

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
	}

	reply(om);
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
	sshlib->hexdump(buf);
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
	# SSH_FXF_READ SSH_FXF_WRITE SSH_FXF_APPEND SSH_FXF_CREAT SSH_FXF_TRUNC SSH_FXF_EXCL SSH_FXF_TEXT
        #uint32        id
        #string        filename
        #uint32        pflags
        #ATTRS         attrs
	v := array[2+len attr.vals] of ref Val;
	v[0] = valstr(path);
	v[1] = valint(pflags);
	v[2:] = attr.vals;
	return sftpwrite(SSH_FXP_OPEN, v);
}

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
