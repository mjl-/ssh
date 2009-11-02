Sftp: module
{
	PATH:	con "/dis/lib/sftp.dis";
	init:	fn();
	dflag:	int;

	Version:	con 3;

	# attribute flags
	SSH_FILEXFER_ATTR_SIZE,
	SSH_FILEXFER_ATTR_UIDGID,
	SSH_FILEXFER_ATTR_PERMISSIONS,
	SSH_FILEXFER_ATTR_ACMODTIME:	con 1<<iota;
	SSH_FILEXFER_ATTR_EXTENDED:	con 16r80000000;

	# open flags
	SSH_FXF_READ,
	SSH_FXF_WRITE,
	SSH_FXF_APPEND,
	SSH_FXF_CREAT,
	SSH_FXF_TRUNC,
	SSH_FXF_EXCL:	con 1<<iota;

	SSH_FILEXFER_TYPE_REGULAR,
	SSH_FILEXFER_TYPE_DIRECTORY,
	SSH_FILEXFER_TYPE_SYMLINK,
	SSH_FILEXFER_TYPE_SPECIAL,
	SSH_FILEXFER_TYPE_UNKNOWN:	con 1+iota;

	# status code
	SSH_FX_OK,
	SSH_FX_EOF,
	SSH_FX_NO_SUCH_FILE,
	SSH_FX_PERMISSION_DENIED,
	SSH_FX_FAILURE,
	SSH_FX_BAD_MESSAGE,
	SSH_FX_NO_CONNECTION,
	SSH_FX_CONNECTION_LOST,
	SSH_FX_OP_UNSUPPORTED,
	SSH_FX_MAX: con iota;

	POSIX_S_IFDIR:	con 8r0040000;

	Attr: adt {
		name:	string;  # from Name response, not really part of attributes
		flags:	int;
		size:	big;
		uid,
		gid:	int;
		perms:	int;
		atime,
		mtime:	int;
		ext:	list of ref (string, string);

		pack:	fn(a: self ref Attr): array of ref Sshfmt->Val;
		isdir:	fn(a: self ref Attr): int;
		dir:	fn(a: self ref Attr, qpath: big, name: string): (Sys->Dir, string);
		text:	fn(a: self ref Attr): string;
	};

	
	Tsftp: adt {
		id:	int;
		pick {
		Init =>
			# "id" is the version
			ext:	list of ref (string, string);
		Open =>
			path:	string;
			flags:	int;
			attr:	ref Attr;
		Close or
		Fstat or
		Readdir =>
			fh:	array of byte;
		Read =>
			fh:	array of byte;
			offset:	big;
			count:	int;
		Write =>
			fh:	array of byte;
			offset:	big;
			data:	array of byte;
		Setstat =>
			path:	string;
			attr:	ref Attr;
		Fsetstat =>
			fh:	array of byte;
			attr:	ref Attr;
		Mkdir =>
			path:	string;
			attr:	ref Attr;
		Lstat or
		Rmdir or
		Realpath or
		Stat or 
		Readlink or
		Opendir or
		Remove =>
			path:	string;
		Rename =>
			opath,
			npath:	string;
		Symlink =>
			linkpath,
			targetpath:	string;
		Ext =>
			name:	string;
			vals:	array of ref Sshfmt->Val;
		}

		pack:		fn(m: self ref Tsftp): array of byte;
		text:		fn(m: self ref Tsftp): string;
	};

	Rsftp: adt {
		id:	int;
		pick {
		Version =>
			# "id" is the version
			exts:		list of ref (string, string);
		Status =>
			status:	int;
			errmsg, lang:	string;
		Handle =>	fh:	array of byte;
		Data =>		buf:	array of byte;
		Name =>		attrs:	array of ref Attr;
		Attrs =>	attr:	ref Attr;
		Extdata =>
			buf:	array of byte;
		}

		read:	fn(fd: ref Sys->FD): (ref Rsftp, string);
		parse:	fn(buf: array of byte): (ref Rsftp, string);
		text:	fn(m: self ref Rsftp): string;
	};
};
