Sshlib: module
{
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

	# new values, for rfc4419
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD:	con 30;
	SSH_MSG_KEX_DH_GEX_GROUP:	con 31;
	SSH_MSG_KEX_DH_GEX_INIT:	con 32;
	SSH_MSG_KEX_DH_GEX_REPLY:	con 33;
	SSH_MSG_KEX_DH_GEX_REQUEST:	con 34;

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

	SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,
	SSH_DISCONNECT_PROTOCOL_ERROR,
	SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
	SSH_DISCONNECT_RESERVED,
	SSH_DISCONNECT_MAC_ERROR,
	SSH_DISCONNECT_COMPRESSION_ERROR,
	SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
	SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
	SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
	SSH_DISCONNECT_CONNECTION_LOST,
	SSH_DISCONNECT_BY_APPLICATION,
	SSH_DISCONNECT_TOO_MANY_CONNECTIONS,
	SSH_DISCONNECT_AUTH_CANCELLED_BY_USER,
	SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
	SSH_DISCONNECT_ILLEGAL_USER_NAME:	con 1+iota;

	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
	SSH_OPEN_CONNECT_FAILED,
	SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
	SSH_OPEN_RESOURCE_SHORTAGE:	con 1+iota;


	msgname:	fn(t: int): string;

	packpacket:	fn(c: ref Sshc, m: ref Tssh): array of byte;
	readpacket:	fn(c: ref Sshc): (ref Rssh, string, string);

	Tssh: adt {
		seq:	big;
		t:	int;
		v:	array of ref Sshfmt->Val;
		minpktlen:	int;
		packed:	array of byte; # ready to be written

		text:	fn(m: self ref Tssh): string;
	};

	Rssh: adt {
		seq:	big;
		t:	int;
		buf:	array of byte; # includes t as first byte

		text:	fn(m: self ref Rssh): string;
	};


	Dgroup1, Dgroup14, Dgroupexchange: con iota;
	Hdss, Hrsa: con iota;
	Enone, Eaes128cbc, Eaes192cbc, Eaes256cbc, Eidea, Earcfour, Eaes128ctr, Eaes192ctr, Eaes256ctr, Earcfour128, Earcfour256, E3descbc, Eblowfish: con iota;
	Mnone, Msha1, Msha1_96, Mmd5, Mmd5_96: con iota;
	Cnone: con iota;
	Apublickey, Apassword: con iota; # add keyboard-interactive

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
			states:	array of ref Keyring->DESstate;
			iv:	array of byte;
		Aesctr =>
			counter,
			key:	array of byte;
		Arcfour2 =>  # rfc4345, discarding first 1536 bytes of key stream
			state:	ref Keyring->RC4state;
		}

		new:	fn(t: int): ref Cryptalg;
		news:	fn(name: string): ref Cryptalg;
		setup:	fn(c: self ref Cryptalg, key, ivec: array of byte);
		crypt:	fn(c: self ref Cryptalg, buf: array of byte, n, direction: int);
	};

	Macalg: adt {
		nbytes:		int;
		keybytes:	int;
		key:		array of byte;
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

	Akex, Ahostkey, Aenc, Amac, Acompr, Aauthmeth: con iota;
	Cfg: adt {
		keyspec:	string;
		kex:		list of string;
		hostkey:	list of string;
		encin,
		encout:		list of string;
		macin,
		macout:		list of string;
		comprin,
		comprout:	list of string;
		authmeth:	list of string;

		default:	fn(): ref Cfg;
		set:		fn(c: self ref Cfg, t: int, l: list of string): string;
		setopt:		fn(c: self ref Cfg, ch: int, s: string): string;
		match:		fn(client, server: ref Cfg): (ref Cfg, string);
		text:		fn(c: self ref Cfg): string;
	};
	parsenames:	fn(s: string): (list of string, string);


	Kex: adt {
		new:	int;
		dhgroup:	ref Dh;
		e, x:	ref Keyring->IPint;
	};

	Dh: adt {
		prime,
		gen:	ref Keyring->IPint;
		nbits:	int;
	};

	Kexinitsent, Kexinitreceived, Newkeyssent, Newkeysreceived, Havenewkeys: con 1<<iota;  # Sshc.state
	Sshc: adt {
		fd:		ref Sys->FD;
		b:		ref Bufio->Iobuf;
		addr,
		user:		string;
		inseq,
		outseq,
		nkeypkts,
		nkeybytes:	big;
		tosrv,
		fromsrv,
		newtosrv,
		newfromsrv:	ref Keys;
		lident,
		rident:		string;
		wantcfg,
		usecfg:		ref Cfg;
		sessionid:	array of byte;
		auths:		list of string; # "rsa", "dsa", "password"

		kexstate:	int;
		kex:		ref Kex;
		clkexinit,
		srvkexinit:	array of byte;	# packets, for use in hash in dh exchange

		kexbusy:	fn(c: self ref Sshc): int;
	};

	handshake:		fn(fd: ref Sys->FD, addr: string, cfg: ref Cfg): (ref Sshc, string);
	keyexchangestart:	fn(c: ref Sshc): ref Tssh;
	keyexchange:		fn(c: ref Sshc, m: ref Rssh): (int, int, list of ref Tssh, string);
	userauth:		fn(c: ref Sshc, m: ref Rssh): (int, int, ref Tssh, string);
	userauthnext:		fn(c: ref Sshc): (ref Tssh, string);
};
