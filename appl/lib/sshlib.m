Sshlib: module {
	PATH:	con "/dis/lib/sshlib.dis";

	dflag:	int;
	init:	fn();

	SSH_MSG_DISCONNECT:		con 1;
	SSH_MSG_IGNORE:			con 2;
	SSH_MSG_UNIMPLEMENTED:		con 3;
	SSH_MSG_DEBUG:			con 4;
	SSH_MSG_SERVICE_REQUEST:	con 5;
	SSH_MSG_SERVICE_ACCEPT:		con 6;
	SSH_MSG_KEXINIT:		con 20;
	SSH_MSG_NEWKEYS:		con 21;
	SSH_MSG_KEXDH_INIT:		con 30;
	SSH_MSG_KEXDH_REPLY:		con 31;
	SSH_MSG_KEXDH_GEX_INIT:		con 32;
	SSH_MSG_KEXDH_GEX_REPLY:	con 33;
	SSH_MSG_KEXDH_GEX_REQUEST:	con 34;


	SSH_MSG_USERAUTH_REQUEST:	con 50;
	SSH_MSG_USERAUTH_FAILURE:	con 51;
	SSH_MSG_USERAUTH_SUCCESS:	con 52;
	SSH_MSG_USERAUTH_BANNER:	con 53;
	SSH_MSG_GLOBAL_REQUEST:		con 80;
	SSH_MSG_REQUEST_SUCCESS:	con 81;
	SSH_MSG_REQUEST_FAILURE:	con 82;
	SSH_MSG_CHANNEL_OPEN:		con 90;
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION:	con 91;
	SSH_MSG_CHANNEL_OPEN_FAILURE:	con 92;
	SSH_MSG_CHANNEL_WINDOW_ADJUST:	con 93;
	SSH_MSG_CHANNEL_DATA:		con 94;
	SSH_MSG_CHANNEL_EXTENDED_DATA:	con 95;
	SSH_MSG_CHANNEL_EOF:		con 96;
	SSH_MSG_CHANNEL_CLOSE:		con 97;
	SSH_MSG_CHANNEL_REQUEST:	con 98;
	SSH_MSG_CHANNEL_SUCCESS:	con 99;
	SSH_MSG_CHANNEL_FAILURE:	con 100;

	SSH_EXTENDED_DATA_STDERR:	con 1;

	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: con -iota-1;

	parseident:	fn(s: string): (string, string, string);
	parsepacket:	fn(buf: array of byte, l: list of int): (array of ref Val, string);
	packpacket:	fn(c: ref Sshc, t: int, a: array of ref Val): array of byte;
	writepacket:	fn(c: ref Sshc, t: int, a: array of ref Val): string;
	writebuf:	fn(c: ref Sshc, d: array of byte): string;
	readpacket:	fn(c: ref Sshc): (array of byte, string);
	hexdump:	fn(d: array of byte);
	sha1bufs:	fn(l: list of array of byte): array of byte;

	getstr:	fn(v: ref Val): array of byte;
	getipint:	fn(v: ref Val): ref Keyring->IPint;
	getint:	fn(v: ref Val): int;
	getbyte:	fn(v: ref Val): byte;
	getbig:	fn(v: ref Val): big;
	hexfp:	fn(d: array of byte): string;
	hex:	fn(d: array of byte): string;
	ipintpack:	fn(v: ref Keyring->IPint): array of byte;
	md5:	fn(d: array of byte): array of byte;

	Val: adt {
		pick {
		Byte =>	v:	byte;
		Bool =>	v:	int;
		Int =>	v:	int;
		Big =>	v:	big;
		Names =>
			l:	list of string;
		Str =>	buf:	array of byte;
		Mpint =>
			v:	ref Keyring->IPint;
		Buf =>	buf:	array of byte;
		}

		packbuf:	fn(v: self ref Val, d: array of byte): int;
		pack:	fn(v: self ref Val): array of byte;
		size:	fn(v: self ref Val): int;
		text:	fn(v: self ref Val): string;
	};

	Enone, Eaes128cbc, Eaes192cbc, Eaes256cbc, Eblowfish, Eidea, Earcfour, Etripledes: con iota;
	Cryptalg: adt {
		bsize:	int;
		keybits:	int;
		pick {
		None =>
		Aes =>
			state:	ref Keyring->AESstate;
		Blowfish =>
			state:	ref Keyring->BFstate;
		Idea =>
			state:	ref Keyring->IDEAstate;
		Arcfour =>
			state:	ref Keyring->RC4state;
		Tripledes =>
			state:	ref Keyring->DESstate;
		}

		new:	fn(t: int): ref Cryptalg;
		news:	fn(name: string): ref Cryptalg;
		setup:	fn(c: self ref Cryptalg, key, ivec: array of byte);
		crypt:	fn(c: self ref Cryptalg, buf: array of byte, n, direction: int);
	};

	Mnone, Msha1, Msha1_96, Mmd5, Mmd5_96: con iota;
	Macalg: adt {
		nbytes:	int;
		key:	array of byte;
		pick {
		None =>
		Sha1 =>
		Sha1_96 =>
		Md5 =>
		Md5_96 =>
		}

		new:	fn(t: int): ref Macalg;
		news:	fn(name: string): ref Macalg;
		setup:	fn(m: self ref Macalg, key: array of byte);
		hash:	fn(m: self ref Macalg, bufs: list of array of byte, hash: array of byte);
	};

	Keys: adt {
		crypt:	ref Cryptalg;
		mac:	ref Macalg;

		new:	fn(cfg: ref Cfg): (ref Keys, ref Keys);
	};

	Akex, Ahostkey, Aenc, Amac, Acompr: con iota;
	Cfg: adt {
		kex:	list of string;
		hostkey:	list of string;
		encin, encout:	list of string;
		macin, macout:	list of string;
		comprin, comprout:	list of string;

		default:	fn(): ref Cfg;
		set:	fn(c: self ref Cfg, t: int, l: list of string): string;
		match:	fn(client, server: ref Cfg): (ref Cfg, string);
		text:	fn(c: self ref Cfg): string;
	};
	parsenames:	fn(s: string): (list of string, string);

	Sshc: adt {
		fd:	ref Sys->FD;
		b:	ref Bufio->Iobuf;
		addr:	string;
		inseq:	int;
		outseq:	int;
		tosrv, fromsrv, newtosrv, newfromsrv:	ref Keys;
		lident, rident:	string;
		cfg:	ref Cfg;

		login:	fn(fd: ref Sys->FD, addr: string, cfg: ref Cfg): (ref Sshc, string);
		text:	fn(s: self ref Sshc): string;
	};
};
