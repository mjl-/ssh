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


Attr.new(isdir: int): ref Attr
{
	a := ref Attr (
		"",
		Sftp->Statflags,
		big 0,
		0, 0,  # uig, gid
		8r666,
		0, 0, # atime, mtime
		nil
	);
	if(isdir)
		a.perms = 8r777|POSIX_S_IFDIR;
	return a;
}

Attr.mk(name: string, a: array of ref Val): ref Attr
{
	flags := a[0].getint();
	size := a[1].getbig();
	uid := a[2].getint();
	gid := a[3].getint();
	perms := a[4].getint();
	atime := a[5].getint();
	mtime := a[6].getint();
	attr := ref Attr (name, flags, size, uid, gid, perms, atime, mtime, nil);
	return attr;
}

Attr.pack(a: self ref Attr): array of ref Val
{
	if(a == nil)
		return nil;
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
		v[i++] = valint(a.mtime);
		v[i++] = valint(a.atime);
	}
	if(flags & int SSH_FILEXFER_ATTR_EXTENDED) {
		v[i++] = valint(len a.ext);
		for(l := a.ext; l != nil; l = tl l) {
			v[i++] = valstr((hd l).t0);
			v[i++] = valstr((hd l).t1);
		}
	}
	return v;
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
	d.uid = string a.uid;
	d.gid = string a.gid;
	d.muid = "none";
	d.qid = Sys->Qid (big 0, 0, Sys->QTFILE);
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

Attr.text(a: self ref Attr): string
{
	if(a == nil)
		return "Attr nil";
	return sprint("Attr (name %q, size %bd, uid/gid %d %d mode %o isdir %d atime %d mtime %d)", a.name, a.size, a.uid, a.gid, a.perms&8r777, a.isdir(), a.atime, a.mtime);
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

xrsftpparse(buf: array of byte): ref Rsftp
{
	lattrs := list of {Tint, Tbig, Tint, Tint, Tint, Tint, Tint};

	o := 0;
	m: array of ref Val;
	(m, o) = xparse(buf, o, list of {Tbyte});
	t := int m[0].getbyte();

say(sprint("rsftpparse, t %d", t));

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
		rm = ref Rsftp.Version (0, version, rev(exts));

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
		say(sprint("names has %d entries", nattr));

		multiattrs: list of int;
		for(i := 0; i < nattr; i++)
			multiattrs = Tstr::Tstr::Tint::Tbig::Tint::Tint::Tint::Tint::Tint::multiattrs;
		stat := xparseall(buf, o, multiattrs);
		for(i = 0; i < len stat; i++)
			say(sprint("stat[%d] = %s", i, stat[i].text()));
		j := 0;
		i = 0;
		attrs := array[nattr] of ref Attr;
		while(j < len stat) {
			say(sprint("stat, o %d, total %d", j, len stat));
			filename := stat[j].getstr();
			attr := Attr.mk(stat[j].getstr(), stat[j+2:j+2+len lattrs]);
			say(sprint("have attr, filename %s, attr %s", filename, attr.text()));
			attrs[i++] = attr;
			j += 2+len lattrs;
		}
		rm = ref Rsftp.Name (id, attrs);

	SSH_FXP_ATTRS =>
		(m, o) = xparse(buf, o, Tint::lattrs);
		id := m[0].getint();
		attr := Attr.mk(nil, m[1:]);
		rm = ref Rsftp.Attrs (id, attr);

	SSH_FXP_EXTENDED_REPLY =>
		(m, o) = xparse(buf, o, list of {Tint});
		id := m[0].getint();
		rm = ref Rsftp.Extdata (id, buf[o:]);

	* =>
		error(sprint("unknown sftp reply, type %d", t));
	}
	say("rsftp message: "+rm.text());
	return rm;
}

rsftptagnames := array[] of {
"Version", "Status", "Handle", "Data", "Name", "Attrs", "Extdata",
};
Rsftp.text(mm: self ref Rsftp): string
{
	s := sprint("Rsftp.%s (", rsftptagnames[tagof mm]);
	pick m := mm {
	Version =>	s += sprint("version %d", m.version);
			for(l := m.exts; l != nil; l = tl l)
				s += sprint(", %q=%q", (hd l).t0, (hd l).t1);
	Status =>	s += sprint("status %d, errmsg %q, lang %q", m.status, m.errmsg, m.lang);
	Handle =>	s += "handle "+hex(m.fh);
	Data =>		s += sprint("len data %d", len m.buf);
	Name =>		s += sprint("len attrs %d", len m.attrs);
	Attrs =>	s += "attr "+m.attr.text();
	}
	s += ")";
	return s;
}


pack(mm: ref Tsftp, v: array of ref Val): array of byte
{
	nv := array[2+len v] of ref Val;
	nv[0] = valbyte(byte tmsgtypes[tagof mm]);
	nv[1] = valintb(mm.id);
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
	Setstat =>
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
	Mkdir =>
		attr := m.attr.pack();
		v := array[1+len attr] of ref Val;
		v[0] = valstr(m.path);
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
	s := sprint("Tsftp.%s(id %bd", tmsgnames[tagof mm], mm.id);
	pick m := mm {
	Init =>		s = sprint("Tsftp.Init(version %bd", m.id);
			for(l := m.ext; l != nil; l = tl l)
				s += sprint(", %q=%q", (hd l).t0, (hd l).t1);
	Open =>		s += sprint(", path %q, flags %#x, %s", m.path, m.flags, m.attr.text());
	Close or
	Fstat or
	Readdir =>	s += sprint(", fh %s", hex(m.fh));
	Read =>		s += sprint(", fh %s, offset %bd, count %d", hex(m.fh), m.offset, m.count);
	Write =>	s += sprint(", fh %s, offset %bd, len data %d", hex(m.fh), m.offset, len m.data);
	Setstat =>	s += sprint(", path %q, %s", m.path, m.attr.text());
	Fsetstat =>	s += sprint(", fh %s, %s", hex(m.fh), m.attr.text());
	Mkdir =>	s += sprint(", path %q, %s", m.path, m.attr.text());
	Lstat or
	Rmdir or
	Realpath or
	Stat or 
	Readlink or
	Opendir or
	Remove =>	s += sprint(", path %q", m.path);
	Rename =>	s += sprint(", opath %q, npath %q", m.opath, m.npath);
	Symlink =>	s += sprint(", linkpath %q, targetpath %q", m.linkpath, m.targetpath);
	Ext =>		s += sprint(", name %q, len values %d", m.name, len m.vals);
	}
	s += ")";
	return s;
}



say(s: string)
{
	if(dflag)
		warn(s);
}
