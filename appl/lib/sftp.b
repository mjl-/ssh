implement Sftp;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "util0.m";
	util: Util0;
	g32i, hex, rev, warn: import util;
include "keyring.m";
include "sshfmt.m";
	sshfmt: Sshfmt;
	Val: import sshfmt;
	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: import sshfmt;
	valbyte, valbool, valint, valintb, valbig, valnames, valstr, valbytes, valmpint: import sshfmt;
include "sftp.m";

Handlemaxlen: con 256;

# requests
SSH_FXP_INIT,
SSH_FXP_VERSION,
SSH_FXP_OPEN,
SSH_FXP_CLOSE,
SSH_FXP_READ,
SSH_FXP_WRITE,
SSH_FXP_LSTAT,
SSH_FXP_FSTAT,
SSH_FXP_SETSTAT,
SSH_FXP_FSETSTAT,
SSH_FXP_OPENDIR,
SSH_FXP_READDIR,
SSH_FXP_REMOVE,
SSH_FXP_MKDIR,
SSH_FXP_RMDIR,
SSH_FXP_REALPATH,
SSH_FXP_STAT,
SSH_FXP_RENAME,
SSH_FXP_READLINK,
SSH_FXP_SYMLINK: con 1+iota;

# responses
SSH_FXP_STATUS,
SSH_FXP_HANDLE,
SSH_FXP_DATA,
SSH_FXP_NAME,
SSH_FXP_ATTRS: con 101+iota;

SSH_FXP_EXTENDED,
SSH_FXP_EXTENDED_REPLY: con 200+iota;


rmsgtypes := array[] of {
tagof Rsftp.Version	=> SSH_FXP_VERSION,
tagof Rsftp.Status	=> SSH_FXP_STATUS,
tagof Rsftp.Handle	=> SSH_FXP_HANDLE,
tagof Rsftp.Data	=> SSH_FXP_DATA,
tagof Rsftp.Name	=> SSH_FXP_NAME,
tagof Rsftp.Attrs	=> SSH_FXP_ATTRS,
tagof Rsftp.Extdata	=> SSH_FXP_EXTENDED_REPLY,
};

tmsgtypes := array[] of {
tagof Tsftp.Init	=> SSH_FXP_INIT,
tagof Tsftp.Open	=> SSH_FXP_OPEN,
tagof Tsftp.Close	=> SSH_FXP_CLOSE,
tagof Tsftp.Fstat	=> SSH_FXP_FSTAT,
tagof Tsftp.Readdir	=> SSH_FXP_READDIR,
tagof Tsftp.Read	=> SSH_FXP_READ,
tagof Tsftp.Write	=> SSH_FXP_WRITE,
tagof Tsftp.Setstat	=> SSH_FXP_SETSTAT,
tagof Tsftp.Fsetstat	=> SSH_FXP_FSETSTAT,
tagof Tsftp.Mkdir	=> SSH_FXP_MKDIR,
tagof Tsftp.Lstat	=> SSH_FXP_LSTAT,
tagof Tsftp.Rmdir	=> SSH_FXP_RMDIR,
tagof Tsftp.Realpath	=> SSH_FXP_REALPATH,
tagof Tsftp.Stat	=> SSH_FXP_STAT,
tagof Tsftp.Readlink	=> SSH_FXP_READLINK,
tagof Tsftp.Opendir	=> SSH_FXP_OPENDIR,
tagof Tsftp.Remove	=> SSH_FXP_REMOVE,
tagof Tsftp.Rename	=> SSH_FXP_RENAME,
tagof Tsftp.Symlink	=> SSH_FXP_SYMLINK,
tagof Tsftp.Ext		=> SSH_FXP_EXTENDED,
};


init()
{
	sys = load Sys Sys->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sshfmt = load Sshfmt Sshfmt->PATH;
	sshfmt->init();
}

Attr.pack(a: self ref Attr): array of ref Val
{
	if(a == nil)
		return array[] of {valint(0)};
	flags := a.flags;
	n := 1;
	if(flags & SSH_FILEXFER_ATTR_SIZE) n += 1;
	if(flags & SSH_FILEXFER_ATTR_UIDGID) n += 2;
	if(flags & SSH_FILEXFER_ATTR_PERMISSIONS) n += 1;
	if(flags & SSH_FILEXFER_ATTR_ACMODTIME) n += 2;
	if(flags & int SSH_FILEXFER_ATTR_EXTENDED) n += 1+len a.ext;

	i := 0;
	v := array[n] of ref Val;
	v[i++] = valint(a.flags);

	if(flags & SSH_FILEXFER_ATTR_SIZE)
		v[i++] = valbig(a.size);
	if(flags & SSH_FILEXFER_ATTR_UIDGID) {
		v[i++] = valint(a.uid);
		v[i++] = valint(a.gid);
	}
	if(flags & SSH_FILEXFER_ATTR_PERMISSIONS)
		v[i++] = valint(a.perms);
	if(flags & SSH_FILEXFER_ATTR_ACMODTIME) {
		v[i++] = valint(a.atime);
		v[i++] = valint(a.mtime);
	}
	if(flags & int SSH_FILEXFER_ATTR_EXTENDED) {
		v[i++] = valint(len a.ext);
		for(l := a.ext; l != nil; l = tl l) {
			v[i++] = valstr((hd l).t0);
			v[i++] = valstr((hd l).t1);
		}
	}
	if(i != len v)
		raise "bad pack";
	return v;
}

Attr.isdir(a: self ref Attr): int
{
	return (a.flags&SSH_FILEXFER_ATTR_PERMISSIONS) && (a.perms&POSIX_S_IFDIR);
}

Attr.dir(a: self ref Attr, qpath: big, name: string): (Sys->Dir, string)
{
	d := sys->nulldir;

	need := SSH_FILEXFER_ATTR_SIZE|SSH_FILEXFER_ATTR_PERMISSIONS;
	if((a.flags & need) != need)
		return (d, "missing fields in attributes from remote");

	d.name = name;
	if(name == nil)
		d.name = a.name;

	if(a.flags & SSH_FILEXFER_ATTR_SIZE)
		d.length = a.size;
	if(a.flags & SSH_FILEXFER_ATTR_UIDGID) {
		d.uid = string a.uid;
		d.gid = string a.gid;
	}
	d.qid = Sys->Qid (qpath, 0, Sys->QTFILE);
	if(a.flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
		d.mode = a.perms&8r777;
		if(a.isdir()) {
			d.qid.qtype = Sys->QTDIR;
			d.mode |= Sys->DMDIR;
		}
	}
	if(a.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
		d.atime = a.atime;
		d.mtime = a.mtime;
	}

	return (d, nil);
}

Attr.text(a: self ref Attr): string
{
	if(a == nil)
		return "Attr nil";
	s := "";
	if(a.name != nil)
		s += sprint(", name %#q", a.name);
	if(a.flags & SSH_FILEXFER_ATTR_SIZE)
		s += sprint(", size %bd", a.size);
	if(a.flags & SSH_FILEXFER_ATTR_UIDGID)
		s += sprint(", uid/gid %d %d", a.uid, a.gid);
	if(a.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
		s += sprint(", perm %o; isdir %d", a.perms&8r777, a.isdir());
	if(a.flags & SSH_FILEXFER_ATTR_ACMODTIME)
		s += sprint(", atime %d, mtime %d", a.atime, a.mtime);
	if(s != nil)
		s = s[2:];
	return "Attr ("+s+")";
}


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
		return (xrsftpparse(buf), nil);
	} exception x {
	"sftp:*" =>
		return (nil, x[5:]);
	}
}

error(s: string)
{
	raise "sftp:"+s;
}

xparseall(buf: array of byte, o: int, l: list of int): array of ref Val
{
	(v, err) := sshfmt->parseall(buf[o:], l);
	if(err != nil)
		error(err);
	return v;
}

xparse(buf: array of byte, o: int, l: list of int): (array of ref Val, int)
{
	(v, no, err) := sshfmt->parse(buf[o:], l);
	if(err != nil)
		error(err);
	return (v, o+no);
}

xattrparse(buf: array of byte, o: int, a: ref Attr): int
{
	m: array of ref Val;
	(m, o) = xparse(buf, o, list of {Tint});
	a.flags = m[0].getint();
	if(a.flags & SSH_FILEXFER_ATTR_SIZE) {
		(m, o) = xparse(buf, o, list of {Tbig});
		a.size = m[0].getbig();
	}
	if(a.flags & SSH_FILEXFER_ATTR_UIDGID) {
		(m, o) = xparse(buf, o, list of {Tint, Tint});
		a.uid = m[0].getint();
		a.gid = m[1].getint();
	}
	if(a.flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
		(m, o) = xparse(buf, o, list of {Tint});
		a.perms = m[0].getint();
	}
	if(a.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
		(m, o) = xparse(buf, o, list of {Tint, Tint});
		a.atime = m[0].getint();
		a.mtime = m[1].getint();
	}
	if(a.flags & int SSH_FILEXFER_ATTR_EXTENDED) {
		(m, o) = xparse(buf, o, list of {Tint});
		n := m[0].getint();
		for(j := 0; j < n; j++) {
			(m, o) = xparse(buf, o, list of {Tint, Tint});
			k := m[0].getstr();
			v := m[1].getstr();
			a.ext = ref (k, v)::a.ext;
		}
		a.ext = rev(a.ext);
	}
	return o;
}

xrsftpparse(buf: array of byte): ref Rsftp
{
	o := 0;
	m: array of ref Val;
	(m, o) = xparse(buf, o, list of {Tbyte});
	t := int m[0].getbyte();

	rm: ref Rsftp;
	case t {
	SSH_FXP_VERSION =>
		(m, o) = xparse(buf, o, list of {Tint});
		version := m[0].getint();

		exts: list of ref (string, string);
		while(o < len buf) {
			(m, o) = xparse(buf, o, list of {Tstr, Tstr});
			name := m[0].getstr();
			data := m[1].getstr();
			exts = ref (name, data)::exts;
			say(sprint("sftp extension: name %q, data %q", name, data));
		}
		rm = ref Rsftp.Version (version, rev(exts));

	SSH_FXP_STATUS =>
		m = xparseall(buf, o, list of {Tint, Tint, Tstr, Tstr});
		rm = sm := ref Rsftp.Status (m[0].getint(), m[1].getint(), m[2].getstr(), m[3].getstr());
		if(sm.status < 0 || sm.status >= SSH_FX_MAX)
			error(sprint("unknown status type %d", t));

	SSH_FXP_HANDLE =>
		m = xparseall(buf, o, list of {Tint, Tstr});
		fh := m[1].getbytes();
		rm = ref Rsftp.Handle (m[0].getint(), fh);
		if(len fh > Handlemaxlen)
			error(sprint("handle too long, max %d, got %d", Handlemaxlen, len fh));

	SSH_FXP_DATA =>
		m = xparseall(buf, o, list of {Tint, Tstr});
		rm = ref Rsftp.Data (m[0].getint(), m[1].getbytes());

	SSH_FXP_NAME =>
		(m, o) = xparse(buf, o, list of {Tint, Tint});
		id := m[0].getint();
		nattr := m[1].getint();

		attrs := array[nattr] of ref Attr;
		for(i := 0; i < nattr; i++) {
			a := ref Attr;
			(m, o) = xparse(buf, o, list of {Tstr, Tstr});
			a.name = m[0].getstr();
			# second is long name, e.g. "ls -l" output

			o = xattrparse(buf, o, a);
			attrs[i] = a;
		}
		if(o != len buf)
			error(sprint("leftover bytes after names message, used %d of %d", o, len buf));
		rm = ref Rsftp.Name (id, attrs);

	SSH_FXP_ATTRS =>
		(m, o) = xparse(buf, o, list of {Tint});
		id := m[0].getint();
		a := ref Attr;
		o = xattrparse(buf, o, a);
		if(o != len buf)
			error(sprint("leftover bytes after attrs message, used %d of %d", o, len buf));
		rm = ref Rsftp.Attrs (id, a);

	SSH_FXP_EXTENDED_REPLY =>
		(m, o) = xparse(buf, o, list of {Tint});
		id := m[0].getint();
		rm = ref Rsftp.Extdata (id, buf[o:]);

	* =>
		error(sprint("unknown sftp reply, type %d", t));
	}
	return rm;
}

rsftptagnames := array[] of {
"Version", "Status", "Handle", "Data", "Name", "Attrs", "Extdata",
};
Rsftp.text(mm: self ref Rsftp): string
{
	s := sprint("Rsftp.%s (id %d", rsftptagnames[tagof mm], mm.id);
	pick m := mm {
	Version =>	s = sprint("Rsftp.Version(version %d", m.id);
			for(l := m.exts; l != nil; l = tl l)
				s += sprint(", %q=%#q", (hd l).t0, (hd l).t1);
	Status =>	s += sprint(", status %d, errmsg %#q, lang %q", m.status, m.errmsg, m.lang);
	Handle =>	s += sprint(", fh %s", hex(m.fh));
	Data =>		s += sprint(", len data %d", len m.buf);
	Name =>		s += sprint(", len attrs %d", len m.attrs);
	Attrs =>	s += ", "+m.attr.text();
	}
	s += ")";
	return s;
}


pack(mm: ref Tsftp, v: array of ref Val): array of byte
{
	nv := array[2+len v] of ref Val;
	nv[0] = valbyte(byte tmsgtypes[tagof mm]);
	nv[1] = valint(mm.id);
	nv[2:] = v;
	return sshfmt->pack(nv, 1);
}

Tsftp.pack(mm: self ref Tsftp): array of byte
{
	pick m := mm {
	Init =>
		v := array[2*len m.ext] of ref Val;
		i := 0;
		for(l := m.ext; l != nil; l = tl l) {
			v[i++] = valstr((hd l).t0);
			v[i++] = valstr((hd l).t1);
		}
		return pack(mm, v);
	Open =>
		attr := m.attr.pack();
		v := array[2+len attr] of {valstr(m.path), valint(m.flags)};
		v[2:] = attr;
		return pack(mm, v);
	Close or
	Fstat or
	Readdir =>
		return pack(mm, array[] of {valbytes(m.fh)});
	Read =>
		return pack(mm, array[] of {valbytes(m.fh), valbig(m.offset), valint(m.count)});
	Write =>
		return pack(mm, array[] of {valbytes(m.fh), valbig(m.offset), valbytes(m.data)});
	Setstat or
	Mkdir =>
		attr := m.attr.pack();
		v := array[1+len attr] of ref Val;
		v[0] = valstr(m.path);
		v[1:] = attr;
		return pack(mm, v);
	Fsetstat =>
		attr := m.attr.pack();
		v := array[1+len attr] of ref Val;
		v[0] = valbytes(m.fh);
		v[1:] = attr;
		return pack(mm, v);
	Lstat or
	Rmdir or
	Realpath or
	Stat or
	Readlink or
	Opendir or
	Remove =>
		return pack(mm, array[] of {valstr(m.path)});
	Rename =>
		return pack(mm, array[] of {valstr(m.opath), valstr(m.npath)});
	Symlink =>
		return pack(mm, array[] of {valstr(m.linkpath), valstr(m.targetpath)});
	Ext =>
		v := array[1+len m.vals] of ref Val;
		v[0] = valstr(m.name);
		v[1:] = m.vals;
		return pack(mm, v);
	}
	raise "internal error";
}

tmsgnames := array[] of {
"Init", "Open", "Close", "Fstat", "Readdir", "Read", "Write", "Setstat", "Fsetstat", "Mkdir",
"Lstat", "Rmdir", "Realpath", "Stat ", "Readlink", "Opendir", "Remove", "Rename", "Symlink", "Ext",
};

Tsftp.text(mm: self ref Tsftp): string
{
	s := sprint("Tsftp.%s(id %d", tmsgnames[tagof mm], mm.id);
	pick m := mm {
	Init =>		s = sprint("Tsftp.Init(version %d", m.id);
			for(l := m.ext; l != nil; l = tl l)
				s += sprint(", %q=%#q", (hd l).t0, (hd l).t1);
	Open =>		s += sprint(", path %#q, flags %#x, %s", m.path, m.flags, m.attr.text());
	Close or
	Fstat or
	Readdir =>	s += sprint(", fh %s", hex(m.fh));
	Read =>		s += sprint(", fh %s, offset %bd, count %d", hex(m.fh), m.offset, m.count);
	Write =>	s += sprint(", fh %s, offset %bd, len data %d", hex(m.fh), m.offset, len m.data);
	Setstat =>	s += sprint(", path %#q, %s", m.path, m.attr.text());
	Fsetstat =>	s += sprint(", fh %s, %s", hex(m.fh), m.attr.text());
	Mkdir =>	s += sprint(", path %#q, %s", m.path, m.attr.text());
	Lstat or
	Rmdir or
	Realpath or
	Stat or 
	Readlink or
	Opendir or
	Remove =>	s += sprint(", path %#q", m.path);
	Rename =>	s += sprint(", opath %#q, npath %#q", m.opath, m.npath);
	Symlink =>	s += sprint(", linkpath %#q, targetpath %#q", m.linkpath, m.targetpath);
	Ext =>		s += sprint(", name %#q, len values %d", m.name, len m.vals);
	}
	s += ")";
	return s;
}

say(s: string)
{
	if(dflag)
		warn(s);
}
