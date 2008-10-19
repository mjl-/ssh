Sshlib: module {
	PATH:	con "/dis/lib/sshlib.dis";

	dflag:	int;
	init:	fn();

	Sshc: adt {
		fd:	ref Sys->FD;

		text:	fn(s: self ref Sshc): string;
	};
};
