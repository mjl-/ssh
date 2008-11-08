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

		pack:	fn(v: self ref Val, d: array of byte): int;
		size:	fn(v: self ref Val): int;
		text:	fn(v: self ref Val): string;
	};

	Keys: adt {
		# no need to store the key or iv here...
		state:	ref Keyring->AESstate; # xxx allow other later
		bsize:	int;
		intkey:	array of byte;
	};

	Sshc: adt {
		fd:	ref Sys->FD;
		b:	ref Bufio->Iobuf;
		inseq:	int;
		outseq:	int;
		tosrv, fromsrv:	ref Keys;

		text:	fn(s: self ref Sshc): string;
	};
};
