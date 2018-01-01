package Net::ICQ2000;


use strict;
no strict 'refs';
use vars qw(
  $VERSION
  %_New_Connection_Nefotiation_Codes
  %_TLV_OUT %_TLV_IN %_TLV_Length_O %_TLV_Length_I %_Srv_Codes
  %_Srv_Decoder %_Cmd_Codes %_Cmd_Encoder
  %_Status_Codes %_r_Status_Codes
);

use Time::Local;
use IO::Socket;
use IO::Select;
use Carp;
# use bytes;


$VERSION = '0.2.1';

sub new {
	my($Package, $UIN, $Password, $AutoConnect, $ServerAddress, $ServerPort) = @_;

	$ServerAddress or $ServerAddress = "login.icq.com";
	$ServerPort or $ServerPort = "5190";

	my $Me = {
		_UIN => $UIN,
		_Password => $Password,
		_Server => $ServerAddress,
		_ServerPort => $ServerPort,
		_Socket => undef,
		_Select => undef,
		_Seq_Num => int(rand(0xFFFF)),
		_Incoming_Queue => [],
		_Outgoing_Queue => [],
		_Connection_Cookie => 0,
		_Hooks => {},
		_Connected => 0,
		_LoggedIn => 0,
		_FLAP_Bytes_Left => 0,
		_FLAP_In_progress => undef,
		_Mem => 1,
		_Auto_Login => 1, #one means minimum, two means full ICQ logon, 0 means none/developer deals with it..
		_Auto_Login_Contact_List => [],
		_Auto_Login_Visible_List => [],
		_Sent_Requests => {},
		_Status => "Online",
		_Debug => 0
	};

	bless($Me, $Package);

	$Me->Connect() if $AutoConnect;

	return $Me;
}


sub Connect {
	my($Me) = @_;

	return if $Me->{_Connected};

	$Me->{_UIN} or croak("Attempted to connect without UIN!");
	$Me->{_Password} or croak("Attempted to connect without Password!");

	$Me->{_Socket} = IO::Socket::INET->new( Proto	 => "tcp",
						PeerAddr  => $Me->{_Server},
						PeerPort  => $Me->{_ServerPort}) or croak("socket error: $@");

	$Me->{_Select} = IO::Select->new($Me->{_Socket});
	$Me->{_Connected} = 1;
}


sub Disconnect {
	my($Me) = @_;

	$Me->{_Connected} or return;

	close($Me->{_Socket});
	$Me->{_Select} = undef;
	$Me->{_Connected} = 0;
	$Me->{_Incoming_Queue} = [];
	$Me->{_Outgoing_Queue} = [];
}


sub Set_Login_Details {
	my($Me, $UIN, $Pass) = @_;

	return if $Me->{_Connected};

	$Me->{_UIN} = $UIN if $UIN;
	$Me->{_Password} = $Pass if $Pass;
}


sub Execute_Once {
	my ($Me) = @_;

	$Me->{_Connected} or return;

	$Me->Check_Incoming;
	$Me->Deal_With_FLAPs;
	$Me->Send_Outgoing;
}

sub Send_Command {
	my ($Me, $Command, $Details) = @_;
	(exists $_Cmd_Codes{$Command}) or return;

	&{$_Cmd_Encoder{$_Cmd_Codes{$Command}}}($Me, $Details) if (exists $_Cmd_Encoder{$_Cmd_Codes{$Command}});
}

sub Add_Hook {
	my($Me, $HookType, $HookFunction) = @_;

	$_Srv_Codes{$HookType} or croak("Bad Hook type!\n");

	$Me->{_Hooks}{$_Srv_Codes{$HookType}} = $HookFunction;
}

%_Status_Codes = (
	'Online'		 => 0x00020000,
	'Free_For_Chat'  => 0x00020020,
	'Away'		   => 0x00020001,
	'Not_Avalible'   => 0x00020005,
	'Occupied'	   => 0x00020011,
	'Do_Not_Disturb' => 0x00020013,
	'Invisible'	  => 0x00120100
);

%_r_Status_Codes = (
	  '0000'  => 'Online',
	  '0020'  => 'Free for Chat',
	  '0001'  => 'Away',
	  '0004'  => 'N/A',
	  '0005'  => 'N/A',
	  '0010'  => 'Occupied',
	  '0011'  => 'Occupied',
	  '0013'  => 'Do Not Disturb',
	  '0100'  => 'Invisible'
);


%_Cmd_Encoder = (
	#Cmd_GSC_Client_Ready
	'1:2' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(1, 2, 0, 0, 2);

		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 3));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 2));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0101));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 3));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x15));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 4));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 6));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 9));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0a));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0110));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x028a));

		push(@{$Me->{_Outgoing_Queue}}, $Responce);

		#turn off the auto login, to save processor time..
		$Me->{_Auto_Login} = 0;
	},
	#Cmd_GSC_Reqest_Rate_Info
	'1:6' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(1, 6, 0, 0, 6);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_GSC_Rate_Info_Ack
	'1:8' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(1, 8, 0, 0, 8);

		#another junk filled responce (AOL must like using up network resources..)
		push(@{$Responce->{Data_Load}}, (0,1,0,2,0,3,0,4,0,5));

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_GSC_LoggedIn_User_Info
	'1:14' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(1, 14, 0, 0, 14);

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_GSC_ICQInform
	'1:23' => sub {
		my($Me, $event) = @_;
		my($Responce);

		#Never changes..
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(1, 0x17, 0, 0, 0x17);
		push(@{$Responce->{Data_Load}}, (0,1,0,3,0,2,0,1,0,3,0,1,0,21,0,1,0,4,0,1,0,6,0,1,0,9,0,1,0,10,0,1));
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_GSC_Set_Status
	'1:30' => sub {
		my($Me, $event) = @_;
		my($Responce, $Responce2);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(1, 30, 0, 0, 30);

		push(@{$Responce->{Data_Load}}, _Write_TLV(2, 'Status', $_Status_Codes{$event->{Status}}));

		push(@{$Me->{_Outgoing_Queue}}, $Responce);

		#send the "Made Change/update command" (really I don't know whta this is for..)
		@{$Responce2->{Data_Load}} = &_Make_SNAC_Header(1, 17, 0, 0, 17);
		push(@{$Responce2->{Data_Load}}, _int_to_bytes(4, 0));

		push(@{$Me->{_Outgoing_Queue}}, $Responce2);
	},
	#Cmd_LS_LoggedIn_User_Rights
	'2:2' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(2, 2, 0, 0, 2);

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_LS_Set_User_Info
	'2:4' => sub {
		my($Me, $event) = @_;
		my($Responce);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(2, 4, 0, 0, 4);

		#if this is setting our details, shouldn't we set something? maybe later.. : )

		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 5));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 32));

		foreach ("09","46","13","49","4c","7f","11","d1","82","22","44","45","53","54","00","00","09","46","13","44","4c","7f","11","d1","82","22","44","45","53","54","00","00"){
			push(@{$Responce->{Data_Load}}, ord);
		}

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_BLM_Rights_Info
	'3:2' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(3, 2, 0, 0, 2);

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_CTL_UploadList
	'3:4' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(3, 4, 0, 0, 4);

		#don't send the command unless we have a list to send..
		return if ($#{$event->{ContactList}} == -1);

		foreach (@{$event->{ContactList}}){
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Mes_Add_ICBM_Param
	'4:2' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(4, 2, 0, 0, 2);

		push(@{$Responce->{Data_Load}}, (0,0,0,0,0,3,0x1f,0x40,3,0xe7,3,0xef,0,0,0,0));
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Mes_Param_Info
	'4:4' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(4, 4, 0, 0, 4);

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_BOS_Get_Rights
	'9:2' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 2, 0, 0, 2);

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_BOS_Add_VisibleList
	'9:5' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 5, 0, 0, 5);

		foreach (@{$event->{VisibleList}}){
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Me->{_Outgoing_Queue}}, $Responce);

	},
	#Cmd_BOS_Add_InVisibleList
	'9:7' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 7, 0, 0, 7);

		foreach (@{$event->{InVisibleList}}){
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Me->{_Outgoing_Queue}}, $Responce);

	},


	#Cmd_Authorize
	'19:26' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 26, 0, 0, 26);
		my$uin = $event->{uin};
		push(@TempPacket, _uin_to_buin($uin));
		push(@TempPacket, _int_to_bytes(1,0x01));
		push(@TempPacket, _int_to_bytes(4,0x00000000));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		# $Me->{_Mem}++;
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Add_ContactList
	'19:20' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 20, 0, 0, 20);

		#don't send the command unless we have a list to send..
		return if ($#{$event->{ContactList}} == -1);

		foreach (@{$event->{ContactList}}){
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x00000000));
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},

	#Cmd_Send_Message
	'4:6' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		if($event->{MessageType} eq 'text')
		{
			@{$Responce->{Data_Load}} = &_Make_SNAC_Header(4, 6, 0, 1, 6);
			my$uin = $event->{uin};
			my$msg = $event->{text};
			my$len = length($msg) + 4;
			push(@TempPacket, _int_to_bytes(4,0x52995d00));
			push(@TempPacket, _int_to_bytes(4,0x69230000));
			push(@TempPacket, _int_to_bytes(2,0x0001));
			push(@TempPacket, _uin_to_buin($uin));
			push(@TempPacket, _int_to_bytes(2,0x0002)); # TLV
			push(@TempPacket, _int_to_bytes(2,$len + 9)); # TLV
			push(@TempPacket, _int_to_bytes(3,0x050100));
			push(@TempPacket, _int_to_bytes(4,0x01010101));
			push(@TempPacket, _int_to_bytes(2,$len));
			push(@TempPacket, _int_to_bytes(2,0));
			push(@TempPacket, _int_to_bytes(2,0xffff));
			push(@TempPacket, _str_to_bytes($msg));
			push(@TempPacket, _int_to_bytes(2,0x0006));
			push(@TempPacket, _int_to_bytes(2,0x0000));
			push(@{$Responce->{Data_Load}}, @TempPacket);
			push(@{$Me->{_Outgoing_Queue}}, $Responce);
		}
		
	},
	#Cmd_Add_List
	'19:8' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 8, 0, 0, 8);
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, 0x00));
		# $Me->{_Mem}++;
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
		push(@TempPacket, _int_to_endian_bytes(4, 41316677));#encode the ICQ num..
		push(@TempPacket, _int_to_bytes(2, 0x7fd1));
		push(@TempPacket, _int_to_bytes(2, 0x7fd1));
		push(@TempPacket, _int_to_bytes(3, 0x0));
		push(@TempPacket, _int_to_bytes(1, 0x4));
		push(@TempPacket, _int_to_bytes(4, 0x01310000));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);

	},

	#Cmd_Srv_Message
	'21:2' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(0x15, 2, 0, 0, ($Me->{_Mem}*65536+0x02)); #strainge request ID..
		$Me->{_Mem}++;

		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0001));

		#Argh, Finally figured this bit out!!!
		#this next four packets is the length in little endian and normal!! so work
		#out the packet length first...

		push(@TempPacket, _int_to_endian_bytes(4, $Me->{_UIN}));#encode the ICQ num..

		if ($event->{MessageType} eq "")
		{
			push(@TempPacket, _int_to_bytes(2, 0x3c00));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(1, 0));
		}
		elsif ($event->{MessageType} eq "ack_offline"){

			push(@TempPacket, _int_to_bytes(2, 0x3e00));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(1, 0));
		}
		elsif ($event->{MessageType} eq "key"){
			print "sending key [$event->{Key}]\n";

			$Me->{_Sent_Requests}{ (($Me->{_Mem}-1)*65536+0x02) } = $event->{Key};

			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));

			push(@TempPacket, _int_to_bytes(3, 0x9808));

			my $Key = "<key>".$event->{Key}."</key>";

			push(@TempPacket, _int_to_endian_bytes(2, length($Key)+1));
			push(@TempPacket, _str_to_bytes($Key));
			push(@TempPacket, _int_to_bytes(1, 0));
		}
		elsif ($event->{MessageType} eq "SMS"){
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));

			push(@TempPacket, _int_to_bytes(4, 0x00821400));
			push(@TempPacket, _int_to_bytes(4, 0x01001600));
			push(@TempPacket, _int_to_bytes(17, 0));

			my $TimeString = gmtime();
			if ($TimeString =~ /(\w+) (\w+) (\d+) (\d+:\d+:\d+) (\d+)/){
				$TimeString = $1.", ".$3." ".$2." ".$5." ".$4." GMT";
			}
			else {
				print "Unable to encode time...\n";
				return;
			}

			my $SMSMessage  = "<icq_sms_message><destination>".$event->{SMS_Dest_Number}."</destination><text>".$event->{text}."</text>";
			   $SMSMessage .= "<codepage>1252</codepage><senders_UIN>".$Me->{_UIN}."</senders_UIN><senders_name>Robbot</senders_name>";
			   $SMSMessage .= "<delivery_receipt>Yes</delivery_receipt><time>$TimeString</time></icq_sms_message>";

			my $SMSLength = length($SMSMessage)+1;

			push(@TempPacket, _int_to_bytes(2, $SMSLength));

			push(@TempPacket, _str_to_bytes($SMSMessage));
			push(@TempPacket, _int_to_bytes(1, 0)); #null end..
		}

		#NOW work out that length thingy (what a crappy place for it!!!)
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, $#TempPacket + 3));
		push(@{$Responce->{Data_Load}}, _int_to_endian_bytes(2, $#TempPacket + 1));
		push(@{$Responce->{Data_Load}}, @TempPacket);

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	}
);

%_Srv_Decoder = (
	#Srv_GSC_Ready
	'1:3' => sub {
		my ($Me, $event) = @_;
		#nothing intresting to get from SNAC..

		if ($Me->{_Auto_Login}){
			$Me->Send_Command("Cmd_GSC_ICQInform");
		}
		return;
	},
	#Srv_GSC_Rate_Info
	"1:7" => sub {
		my ($Me, $event) = @_;
		#my ($Refined);

		if ($Me->{_Auto_Login} > 1){
			#ack the rate info..
			$Me->Send_Command("Cmd_GSC_Rate_Info_Ack");

			#also send some other requests..
			$Me->Send_Command("Cmd_GSC_LoggedIn_User_Info");
			$Me->Send_Command("Cmd_LS_LoggedIn_User_Rights");
			$Me->Send_Command("Cmd_BLM_Rights_Info");
			$Me->Send_Command("Cmd_Mes_Param_Info");
			$Me->Send_Command("Cmd_BOS_Get_Rights");
		}

		#Loads of data, but I have no idea what to do with it..
		#(tells us all the posible commands?..)
		return ($event);
	},
	#Srv_GSC_User_Info
	'1:15' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $i, $DataLength);

		#$event->{Data_Load}

		$i = 10;

		$DataLength = ${$event->{Data_Load}}[$i];

		$i++;
		$Refined->{Online_User} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);
		$i += $DataLength;
		$Refined->{Warning_Lev} = _bytes_to_int ($event->{Data_Load}, $i, 2);
		$i += 4;

		($Refined, $i) = &_Read_TLV($event->{Data_Load}, 2, $i, $Refined);
		return ($Refined);
	},
	#Srv_GSC_MOTD
	'1:19' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $i);

		$i = 12;

		($Refined, $i) = &_Read_TLV($event->{Data_Load}, 2, $i, $Refined);
		return ($Refined);
	},
	#Srv_GSC_ICQClientConfirm
	'1:24' => sub {
		my ($Me, $event) = @_;
		my ($Refined);

		#$event->{Data_Load}

		if ($Me->{_Auto_Login}){
			if ($Me->{_Auto_Login} == 1){
				my ($details);

				$details->{Status} = $Me->{_Status};
				$Me->Send_Command("Cmd_CTL_UploadList", {ContactList=> $Me->{_Auto_Login_Contact_List}});
				if($Me->{_Status} eq 'Invisible')
				{
					$Me->Send_Command("Cmd_BOS_Add_VisibleList", {VisibleList=> $Me->{_Auto_Login_Visible_List}});
				}
				$Me->Send_Command("Cmd_GSC_Set_Status", $details);
				$Me->Send_Command("Cmd_GSC_Client_Ready");
				$Me->Send_Command("Cmd_Srv_Message");
				$Me->{_LoggedIn} = 1;
			}
			else {
				$Me->Send_Command("Cmd_GSC_Reqest_Rate_Info");
			}
		}
		return ($Refined);
	},
	#Srv_LS_Rights_Response
	'2:3' => sub  {
		my ($Me, $event) = @_;
		my ($Refined);

		#no idea what to do with this data..
		#$event->{Data_Load}
		return ($Refined);
	},
	#Srv_BLM_Rights_Response
	'3:3' => sub  {
		my ($Me, $event) = @_;
		my ($Refined);

		#no idea what to do with this data..
		#$event->{Data_Load}
		return ($Refined);
	},
	#Srv_BLM_Contact_Online
	'3:11' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $DataLength, $i);

		$i = 10;
		$DataLength = ${$event->{Data_Load}}[$i];$i++;

		$Refined->{UIN} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);$i += $DataLength + 4;

		($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, _bytes_to_int($event->{Data_Load}, $i-4, 4));

		return ($Refined);
	},
	#Srv_BLM_Contact_Offline
	'3:12' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $DataLength, $i);

		$i = 10;
		$DataLength = ${$event->{Data_Load}}[$i];$i++;

		$Refined->{UIN} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);$i += $DataLength + 4;

		($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, _bytes_to_int($event->{Data_Load}, $i-4, 4));

		return ($Refined);
	},
	#Srv_Mes_Rights_Response
	'4:5' => sub  {
		my ($Me, $event) = @_;
		my ($Refined);

		#no idea what to do with this data..
		#$event->{Data_Load}
		return ($Refined);
	},
	#Srv_Mes_Received
	'4:7' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $i, $DataLength, $DataType);

		print "Incomming..\n" if $Me->{_Debug};
		_print_packet($event->{Data_Load}, ()) if $Me->{_Debug};

		$i = 19;

		$Refined->{SenderType} = $event->{Data_Load}->[$i];$i++;

		$DataLength = ${$event->{Data_Load}}[$i];$i++;

		$Refined->{Sender} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);$i += $DataLength + 4;

		($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, _bytes_to_int($event->{Data_Load}, $i-4, 4));

		if ($Refined->{Encoded_Message}){
			#this is a weird ass message, so decode it..
			my @Encoded_Message = split(/ /, $Refined->{Encoded_Message});
			undef $Refined->{Encoded_Message};

			$Refined->{TaggedDataString} = _bytes_to_str(\@Encoded_Message, 0x32, _endian_bytes_to_int(\@Encoded_Message, 0x2f, 2));

			_Decode_Tagged_Text($Refined->{TaggedDataString}, $Refined);

			return ($Refined);
		}
		$Refined->{Message_Encoding} = _bytes_to_int($event->{Data_Load}, $i, 2); $i+=2;

		# print "==> $Refined->{Message_Encoding}\n";
		if ($Refined->{Message_Encoding} == 2){
			#normal text message..
			$Refined->{MessageType} = "Normal";

			$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
			$i += 15;

			$DataLength -= 13;

			$Refined->{text} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);
		}elsif ($Refined->{Message_Encoding} == 5){
			$DataLength = _bytes_to_int($event->{Data_Load}, $i, 2);
			$i+=2;
			$i+=4;
			my $type = ord(_bytes_to_str($event->{Data_Load}, $i, 1));
			$i++;
			# my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
			# my @bytes = _str_to_bytes($data);
			# print ">> [$type] @bytes <<\n";
			#print "$bytes[2]\n";
			if($type == 12) # Auth request!
			{
				$i++;
				my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
				my($nick,$fname,$lname,$email,$xxx,$reason); 
				($nick,$fname,$lname,$email,$xxx,$reason) = split /\xfe/,$data;
				$Refined->{nick} = $nick;
				$Refined->{first_name} = $fname;
				$Refined->{last_name} = $lname;
				$Refined->{email} = $email;
				$Refined->{reason} = $reason;
				$Refined->{MessageType} = "auth_request";
			}	
			elsif($type == 4) # URL
			{
					$Refined->{MessageType} = "URL";
					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					($Refined->{Description},$Refined->{URL}) = split /\xfe/,$data;
			}
			elsif($type == 26) # Contact request
			{
					my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4); #$DataLength-4);
					my @bytes = _str_to_bytes($data);
					$i = $bytes[2]-1;
					my $reason = '';
					foreach (@bytes[$i+1..$i+$bytes[$i]])
					{
						$reason .= chr;
					}
					
					$Refined->{MessageType} = "contacts_request";
					$Refined->{Reason} = $reason;
			}


			elsif($type == 19) # Auth request!
			{
				$i+=2;
				my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
				my ($contactcount,@contacts) = split /\xfe/,$data;
				# print "Got $contactcount contacts!\n";
				# $j = 0;
				# while($ <= $#contacts)
				# {
					# print $contacts[$i]. " " . $contacts[$i+1] . "\n";
					# $i+=2;
				# }
				$Refined->{MessageType} = "contacts";
				$Refined->{Count} = $contactcount;
				$Refined->{Contacts} = \@contacts;
			}
		}


		return ($Refined);
	},
	#Srv_BOS_Rights
	'9:3' => sub {
		my ($Me, $event) = @_;
		my ($Refined);

		if ($Me->{_Auto_Login} > 1){

			$Me->Send_Command("Cmd_Mes_Add_ICBM_Param");
			$Me->Send_Command("Cmd_LS_Set_User_Info");

			$Me->Send_Command("Cmd_CTL_UploadList", {ContactList=> $Me->{_Auto_Login_Contact_List}});

			$Me->Send_Command("Cmd_GSC_Set_Status", {Status => $Me->{_Status}});
			$Me->Send_Command("Cmd_GSC_Client_Ready");

			#now send all the Ad requests (hey, this is how the client does it.. : /
			$Me->Send_Command("Cmd_Srv_Message");
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "key", Key => "DataFilesIP"});
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "key", Key => "BannersIP"});
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "key", Key => "ChannelsIP"});

		}
		#$event->{Data_Load}
		return ($Refined);
	},
	#Srv_Srv_Message
	'21:3' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $i);

		################
		##### NOTE #####
		################
		#This Srv responce seems to be the one that AOL desided to hack ALL ICQ functions that
		# they couldn't fit under the normal AIM protocol. This means that this family
		# seems to ave a lot of sub sub sub families, and hence is a bastard to decode,
		# and then when u think u've got it, one call out of 900000 screws up in the decoding
		# so if anyone has some good insights into this family please let me know!!!!

		print "Incomming..\n" if $Me->{_Debug};
		print "[".$event->{Channel_ID}."][".$event->{Sequence_ID}."][".$event->{Data_Size}."][".$event->{Family_ID}."][".$event->{Sub_ID}."]\n" if $Me->{_Debug};
		_print_packet($event->{Data_Load}, ()) if $Me->{_Debug};

		$Refined->{Flags} = _bytes_to_int($event->{Data_Load}, 4, 2);
		$Refined->{Ref} = _bytes_to_int($event->{Data_Load}, 6, 4);

		if (exists $Me->{_Sent_Requests}{$Refined->{Ref}}){
			$Refined->{Responce_Type} = $Me->{_Sent_Requests}{$Refined->{Ref}};
			undef $Me->{_Sent_Requests}{$Refined->{Ref}};
		}

		#first ten is SNAC header, then a 00 01 (normally..) then the message's size in
		#Normal then endian format (don't have any idea why, but it is..) but skip all that..
		$i = 16;
		$Refined->{Our_UIN} = _endian_bytes_to_int($event->{Data_Load}, $i, 4);$i += 4;

		#the first of the sub sub types..
		$Refined->{MessageType} = _endian_bytes_to_int($event->{Data_Load}, $i, 2);$i += 2;
		if ($Refined->{MessageType} == 65){
			# normally offline messages..
			if (_endian_bytes_to_int($event->{Data_Load}, $i, 2) == 2){
				#90% sure it's an offline message..
				$i += 2;
				$Refined->{Sender} = _endian_bytes_to_int($event->{Data_Load}, $i, 4);$i += 4;

				#note, the time given is in GMT, not local, so make it local..(DIE AOL!!!)
				$Refined->{Sent_Time} = localtime(timegm(0,
						   _endian_bytes_to_int($event->{Data_Load}, $i+5, 1),
						   _endian_bytes_to_int($event->{Data_Load}, $i+4, 1),
						   _endian_bytes_to_int($event->{Data_Load}, $i+3, 1),
						   _endian_bytes_to_int($event->{Data_Load}, $i+2, 1)-1,
						   _endian_bytes_to_int($event->{Data_Load}, $i,   2)));
				$i += 6;
				
				$Refined->{Message_Encoding} = _endian_bytes_to_int($event->{Data_Load}, $i,   1);
				$Refined->{Message_Flags} = _endian_bytes_to_int($event->{Data_Load}, $i,   1);
				$i+=2;
				my $DataLength=0;
				if ($Refined->{Message_Encoding} == 1){
					#normal text message..
					$Refined->{MessageType} = "Normal";
					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					$Refined->{text} = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
				}elsif ($Refined->{Message_Encoding} == 4)
				{
					$Refined->{MessageType} = "URL";
					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					($Refined->{Description},$Refined->{URL}) = split /\xfe/,$data;
				}elsif ($Refined->{Message_Encoding} == 5)
				{
					my $DataLength = _bytes_to_int($event->{Data_Load}, $i, 2);
					$i+=2;
					$i+=4;
					my $type = ord(_bytes_to_str($event->{Data_Load}, $i, 1));
					$i++;
					if($type == 12) # Auth request!
					{
						$i++;
						my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
						my($nick,$fname,$lname,$email,$xxx,$reason); 
						($nick,$fname,$lname,$email,$xxx,$reason) = split /\xfe/,$data;
						$Refined->{nick} = $nick;
						$Refined->{first_name} = $fname;
						$Refined->{last_name} = $lname;
						$Refined->{email} = $email;
						$Refined->{reason} = $reason;
						$Refined->{MessageType} = "auth_request";
					}	
					elsif($type == 19) # contacts
					{
						$i+=2;
						my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
						my ($contactcount,@contacts) = split /\xfe/,$data;
						$Refined->{MessageType} = "contacts";
						$Refined->{Count} = $contactcount;
						$Refined->{Contacts} = \@contacts;
					}

				}elsif ($Refined->{Message_Encoding} == 26)
				{
					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					my @bytes = _str_to_bytes($data);
					$i = $bytes[1]-2;
					my $reason = '';
					foreach (@bytes[$i+1..$i+$bytes[$i]])
					{
						$reason .= chr;
					}
					

					$Refined->{MessageType} = "contacts_request";
					$Refined->{Reason} = $reason;
				}

			}
			else {
				print "Argh, something Screwed up!!!";
				return;
			}
		}
		elsif ($Refined->{MessageType} == 66){ 
			# End of offline messages
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "ack_offline"});
			$Refined->{MessageType} = "ack_offline";
		}
		elsif ($Refined->{MessageType} == 2010){
			#Server messages stored in "html" style tags..
			$i += 2;

			if (_bytes_to_int($event->{Data_Load}, $i, 2) == 41480) {
				#short gap.. (this is a VERY bad way of doing this.. should fix..)
				$i += 3;
			}
			else {
				#don't know what these 11(?) bytes do..
				$i += 11;
			}

			$Refined->{TaggedDataString} = _bytes_to_str($event->{Data_Load}, $i+2, _bytes_to_int($event->{Data_Load}, $i, 2));
			_Decode_Tagged_Text($Refined->{TaggedDataString}, $Refined);
		}

		return ($Refined);
	}
);

%_Cmd_Codes = (
	Cmd_GSC_Client_Ready		=> "1:2",
	Cmd_GSC_Reqest_Rate_Info	=> "1:6",
	Cmd_GSC_LoggedIn_User_Info  => "1:14",
	Cmd_GSC_ICQInform		   => "1:23",
	Cmd_GSC_Set_Status		  => "1:30",
	Cmd_LS_LoggedIn_User_Rights => "2:2",
	Cmd_LS_Set_User_Info		=> "2:4",
	Cmd_BLM_Rights_Info		 => "3:2",
	Cmd_CTL_UploadList		  => "3:4",
	Cmd_Mes_Add_ICBM_Param	  => "4:2",
	Cmd_Mes_Param_Info		  => "4:4",
	Cmd_BOS_Get_Rights		  => "9:2",
	Cmd_BOS_Add_VisibleList	 => "9:5",
	Cmd_BOS_Add_InVisibleList   => "9:7",
	Cmd_Srv_Message			 => "21:2",
	Cmd_Send_Message			=> "4:6",
	Cmd_Add_ContactList			=> "19:20",
	Cmd_Authorize				=> "19:26"
);



%_Srv_Codes = (
	Srv_GSC_Error		   => "1:1",
	Srv_GSC_Ready		   => "1:3",
	Srv_GSC_Redirect		=> "1:5",
	Srv_GSC_Rate_Info	   => "1:7",
	Srv_GSC_Rate_Change	 => "1:10",
	Srv_GSC_User_Info	   => "1:15",
	Srv_GSC_MOTD			=> "1:19",
	Srv_GSC_ICQClientConfirm=> "1:24",
	Srv_LS_Rights_Response  => "2:3",
	Srv_BLM_Rights_Response => "3:3",
	Srv_BLM_Contact_Online  => "3:11",
	Srv_BLM_Contact_Offline => "3:12",
	Srv_Mes_Rights_Response => "4:5",
	Srv_Mes_Received		=> "4:7",
	Srv_BOS_Rights		  => "9:3",
	Srv_Srv_Message		 => "21:3"
);


%_New_Connection_Nefotiation_Codes = (
	1 => sub {
		my ($Me, $event) = @_;
		my($Responce);

		print "Sending Connection reply..\n";

		if ($Me->{_Connection_Cookie}){
			print "Sending Cookie\n";
			#Second time connected, so send the cookie..
			$Responce->{Channel_ID} = 1;
			@{$Responce->{Data_Load}} = _int_to_bytes(4, 1);
			push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'Connection_Cookie', $Me->{_Connection_Cookie}));

			push(@{$Me->{_Outgoing_Queue}}, $Responce);

			#wipe the now used cookie (eat? :)
			$Me->{_Connection_Cookie} = 0;
			return;
		}

		#send our login details..
		$Responce->{Channel_ID} = 1;
		@{$Responce->{Data_Load}} = _int_to_bytes(2, 0);
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 1));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'UIN',	  $Me->{_UIN}));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'Password', &_Password_Encrypt($Me->{_Password})));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientProfile', "ICQ Inc. - Product of ICQ (TM).2000b.4.63.1.3279.85"));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientType', 266));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientVersionMajor', 4));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientVersionMinor', 63));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientICQNumber',	1));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientBuildMajor',   3279));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientBuildMinor',   85));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'Language',		   "en"));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'CountryCode',		"us"));

		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	}
);

sub _Disconnection_Nefotiation {
	my ($Me, $event) = @_;
	my ($Details, $i);

	print "Incomming..\n" if $Me->{_Debug};
	_print_packet($event->{Data_Load}, ())  if $Me->{_Debug};

	($Details, $i) = &_Read_TLV($event->{Data_Load}, 4);

	croak("Server got our UIN wrong!![".$Details->{UIN}."]") if ($Details->{UIN} != $Me->{_UIN});

	$Me->{_Connection_Cookie} = $Details->{Connection_Cookie} if ($Details->{Connection_Cookie});

	if ($Details->{Server_And_Port}){
		#we've been told to disconnect, and reconnect...
		print "Disconnecting as instructed..\n";
		$Me->Disconnect();

		#change the server we are going to access...
		($Me->{_Server}, $Me->{_ServerPort}) = split (/:/, $Details->{Server_And_Port});
		print "Changing to server [".$Me->{_Server}."][".$Me->{_ServerPort}."]\n" if ($Me->{_Debug});

		$Me->Connect();
	}
	elsif ($Details->{Password_Error}){
		#run the PasswordError hook 9,9
		if (exists $Me->{_Hooks}{$_->{9}{9}} ) {
			&{$Me->{_Hooks}{9}{9}}($Me, $_)
		}
	}
	elsif ($Details->{Dual_User_Online}){
		#run the DualUserError hook 9,10
		if (exists $Me->{_Hooks}{$_->{9}{10}} ) {
			&{$Me->{_Hooks}{9}{10}}($Me, $_)
		}
	}
}

sub Check_Incoming {
	my ($Me) = @_;
	my($RawPacket, @Packet);

	while (IO::Select->select($Me->{_Select}, undef, undef, .00001)) {
		$Me->{_Socket}->recv($RawPacket, 10000);

		if (!$RawPacket) {
			$Me->Disconnect;
			return;
		}

		@Packet =  split(//, $RawPacket);

		foreach (@Packet){
			$_ = ord;
		}

		my $PLength = @Packet;
		#decode the packet into FLAPs
		for(my $i =0; $i < $PLength; $i++){

			if ($Me->{_FLAP_Bytes_Left} > 0){
				push (@{$Me->{_FLAP_In_progress}{Data_Load}},  $Packet[$i]);

				$Me->{_FLAP_Bytes_Left}--;

				if ($Me->{_FLAP_Bytes_Left} <= 0){
					#end the FLAP, and move it to the Queue..
					push(@{$Me->{_Incoming_Queue}}, $Me->{_FLAP_In_progress});
					$Me->{_FLAP_In_progress} = undef;
					$Me->{_FLAP_Bytes_Left} = 0;
				}
				next;
			}

			#it's a new FLAP..
			$Packet[$i] == 42 or croak("Recieved Data Missaligned!");

			$Me->{_FLAP_In_progress}{Channel_ID}	= _bytes_to_int(\@Packet, $i+1, 1);
			$Me->{_FLAP_In_progress}{Sequence_ID}   = _bytes_to_int(\@Packet, $i+2, 2);
			$Me->{_FLAP_In_progress}{Data_Size}	 = $Me->{_FLAP_Bytes_Left} = _bytes_to_int(\@Packet, $i+4, 2);
			$Me->{_FLAP_In_progress}{Family_ID}	 = _bytes_to_int(\@Packet, $i+6, 2);
			$Me->{_FLAP_In_progress}{Sub_ID}		= _bytes_to_int(\@Packet, $i+8, 2);

			$i +=5;
		}
	}
}

sub Deal_With_FLAPs {
	my($Me) = @_;

	foreach (@{$Me->{_Incoming_Queue}}){
		if ($_->{Channel_ID} == 1){
			#login system message, deal with it..
			if ( exists $_New_Connection_Nefotiation_Codes{$_->{Sub_ID}} ) {
				print "Found Connection Event, Dealing with it,,\n";
				&{$_New_Connection_Nefotiation_Codes{$_->{Sub_ID}}}($Me, $_);
			}

		}
		elsif ($_->{Channel_ID} == 2){
			#This is a non critical FLAP. so decode, and pass to a hook if there is one..
			my $ID = $_->{Family_ID}.":".$_->{Sub_ID};
			# print "\n==> $ID\n";

			if (exists $Me->{_Hooks}{$ID} ) {

				#decode the Sub_ID etc..
				print "can't run sub!![$ID]\n" if ( !(exists $_Srv_Decoder{$ID}) );

				my ($Refined);

				$Refined = &{$_Srv_Decoder{$ID}}($Me, $_)	if ( exists $_Srv_Decoder{$ID} );

				#run the Hook..
				&{$Me->{_Hooks}{$ID}}($Me, $Refined);
			}
			elsif ($Me->{_Auto_Login}){

				&{$_Srv_Decoder{$ID}}($Me, $_)	if ( exists $_Srv_Decoder{$ID} );
			}
			elsif ($Me->{_Debug}){
				print "Incomming..\n" if $Me->{_Debug};
				print "[".$_->{Channel_ID}."][".$_->{Sequence_ID}."][".$_->{Data_Size}."][".$_->{Family_ID}."][".$_->{Sub_ID}."]\n";
				_print_packet($_->{Data_Load}, ());
			}
		}
		elsif ($_->{Channel_ID} == 4){
			print "Found DisConnection Event, Dealing with it,,\n";
			&_Disconnection_Nefotiation($Me, $_);
		}
		else {
			#this is an error type  message..
		}

	}
	$Me->{_Incoming_Queue} = [];
}

sub Send_Outgoing {
	my($Me) = @_;
	my($Chan, $Data_Size, @Header, $Raw_Data);

	foreach (@{$Me->{_Outgoing_Queue}}){

		if ($_->{Channel_ID}){$Chan = $_->{Channel_ID};}else {$Chan = 2;}
		$Data_Size = @{$_->{Data_Load}};

		@Header = (42, $Chan);

		$Me->{_Seq_Num}++;
		$Me->{_Seq_Num} = 0 if $Me->{_Seq_Num} > 65535;

		push(@Header, _int_to_bytes(2, $Me->{_Seq_Num}));
		push(@Header, _int_to_bytes(2, $Data_Size));

		foreach (@Header){
			$Raw_Data .= chr($_);
		}
		foreach (@{$_->{Data_Load}}){
			$Raw_Data .= chr($_);
		}

		print "Outgoing..\n" if $Me->{_Debug};
		_print_packet(\@Header, \@{$_->{Data_Load}}) if $Me->{_Debug};
	}

	#send them all off..
	if ($Raw_Data) {
		$Me->{_Socket}->send($Raw_Data);
	}

	$Me->{_Outgoing_Queue} = [];
}

#########################
### Private functions ###
#########################

#These functions should only ever be run from within the ICQ object..




# _bytes_to_int(array_ref, start, bytes)
#
# Converts the byte array referenced by <array_ref>, starting at offset
# <start> and running for <bytes> values, into an integer, and returns it.
# The bytes in the array must be in little-endian order.
#
# _bytes_to_int([0x34, 0x12, 0xAA, 0xBB], 0, 2) == 0x1234
# _bytes_to_int([0x34, 0x12, 0xAA, 0xBB], 2, 1) == 0xAA

sub _endian_bytes_to_int {
  my ($array, $start, $bytes) = @_;
  my ($ret);

  $ret = 0;
  for (my $i = $start+$bytes-1; $i >= $start; $i--) {
	$ret <<= 8;
	$ret |= ($array->[$i] or 0);
  }

  return $ret;
}

sub _bytes_to_int {
  my ($array, $start, $bytes) = @_;
  my ($ret);

  $ret = 0;
  for (my $i = $start; $i < $start+$bytes; $i++) {
	$ret <<= 8;
	$ret |= ($array->[$i] or 0);
  }

  return $ret;
}

# _int_to_endian_bytes(bytes, val)
#
# Converts <val> into an array of <bytes> bytes and returns it.
# If <val> is too big, only the <bytes> least significant bytes are
# returned.  The array is in little-endian order.
#
# _int_to_bytes(2, 0x1234)  == (0x34, 0x12)
# _int_to_bytes(2, 0x12345) == (0x45, 0x23)

sub _int_to_endian_bytes {
  my ($bytes, $val) = @_;
  my (@ret);

  for (my $i=0; $i<$bytes; $i++) {
	push @ret, ($val >> ($i*8) & 0xFF);
  }

  return @ret;
}

# _int_to_bytes(bytes, val)
#
# Converts <val> into an array of <bytes> bytes and returns it.
# If <val> is too big, only the <bytes> least significant bytes are
# returned.  The array is not little-endian order.
#
# _int_to_bytes(2, 0x1234)  == (0x12, 0x34)
# _int_to_bytes(2, 0x12345) == (0x12, 0x34)

sub _int_to_bytes {
  my ($bytes, $val) = @_;
  my (@ret);

  for (my $i=0; $i<$bytes; $i++) {
	unshift @ret, ($val >> ($i*8) & 0xFF);
  }

  return @ret;
}

# _str_to_bytes(str, add_zero)
#
# Converts <str> into an array of bytes and returns it.
#
# _str_to_bytes('foo')	 == ('f', 'o', 'o')

sub _str_to_bytes {
  my ($string) = @_;
  my (@ret);

  # the ?: keeps split() from complaining about undefined values
  foreach (split(//, defined($string) ? $string : '')) {
	push @ret, ord($_);
  }

  return @ret;
}


# _uin_to_buin(str, add_zero)
#
# Converts <str> into an array of bytes and returns it.
#
# _str_to_bytes('foo')	 == ('f', 'o', 'o')

sub _uin_to_buin {
  my ($uin) = @_;
  my (@ret);
  push @ret, length($uin);
  # the ?: keeps split() from complaining about undefined values
  foreach (split(//, defined($uin) ? $uin : '')) {
	push @ret, ord($_);
  }

  return @ret;
}


# _bytes_to_str(array_ref, start, bytes)
#
# Converts the byte array referenced by <array_ref>, starting at offset
# <start> and running for <bytes> values, into a string, and returns it.
#
# _bytes_to_str([0x12, 'f', 'o', 'o', '!'], 1, 3) == 'foo'

sub _bytes_to_str {
  # thanks to Dimitar Peikov for the fix
  my ($array, $start, $bytes) = @_;
  my ($ret);

  $ret = '';
  for (my $i = $start; $i < $start+$bytes; $i++) {
	$ret .= $array->[$i] ? chr($array->[$i]) : '';
  }

  return $ret;
}

# print_packet(Header_packet_ref, Body_packet_ref)
#
# Dumps the ICQ packet contained in the byte array referenced by
# <packet_ref> to STDOUT.

sub _print_packet {
	my ($Header, $packet) = @_;
	my ($Counter, $TLine);

	foreach (@$Header) {
		$Counter++;

		print sprintf("%02X ", $_);

		if ($_ >= 32){
			$TLine .= chr($_);
		}
		else {
			$TLine .= ".";
		}

		if ($Counter % 16 == 0){
			print "  ".$TLine."\n";
			$TLine = '';
		}
	}
	while ($Counter > 16){$Counter -=16}

	if (16 - $Counter > 1 && $Counter > 0){
		foreach (1..(16 - $Counter)){
			print "   ";
		}
		print "  ".$TLine."\n";
	}
	$TLine ='';
	$Counter =0;

	foreach (@$packet) {
		$Counter++;

		print sprintf("%02X ", $_);

		if ($_ >= 32){
			$TLine .= chr($_);
		}
		else {
			$TLine .= ".";
		}

		if ($Counter % 16 == 0){
			print "  ".$TLine."\n";
			$TLine = '';
		}
	}
	while ($Counter > 16){$Counter -=16}

	if (16 - $Counter > 1 && $Counter > 0){
		foreach (1..(16 - $Counter)){
			print "   ";
		}
		print "  ".$TLine."\n";
	}
	print "\n";
}

# _Password_Encrypt(Password_String)
# Encrypts the password for sending to the server using a simple XOR "encryption" method
sub _Password_Encrypt {
	my ($Password) = @_;
	my ($FinishedString);

	my @Pass = split (//, $Password);

	foreach (@Pass){
		$_ = ord($_);
	}

	my @encoding_table = (
		0xf3, 0x26, 0x81, 0xc4,
		0x39, 0x86, 0xdb, 0x92,
		0x71, 0xa3, 0xb9, 0xe6,
		0x53, 0x7a, 0x95, 0x7c);

	for (my $i = 0; $i < length($Password); $i++){
		$FinishedString .= chr($Pass[$i] ^ $encoding_table[$i]);
	}

	return ($FinishedString);
}

# _Make_SNAC_Header(Comand_Family, Sub_Family, FlagA, FlagB, RequestID)
#makes the SNAC header which has to be at the top of every command..

sub _Make_SNAC_Header {
	my($Family, $Sub_Family, $FlagA, $FlagB, $RequestID) = @_;
	my (@Header);

		@Header = _int_to_bytes(2, $Family);
	push(@Header, _int_to_bytes(2, $Sub_Family));
	push(@Header, _int_to_bytes(1, $FlagA));
	push(@Header, _int_to_bytes(1, $FlagB));
	push(@Header, _int_to_bytes(4, $RequestID));

	return @Header;
}

#this function takes a tagged string (like the server sends..) and breaks it up into
# it's parts...

sub _Decode_Tagged_Text {
	my($String, $Details) = @_;
	my($Key, $Data, $i);

	my @Entries = split (/</, $String);
	if ($Entries[4]){
		chop $Entries[1];

		$Details->{MessageType} = $Entries[1];

		$i = 2;
	}
	else {
		$i = 1;
	}

	while ($Entries[$i] && $Entries[$i+1]){
		($Key, $Data) = split(/>/, $Entries[$i]);

		$Details->{$Key} = $Data;
		$i += 2;
	}
	return ($Details);
}

#####################
### TLV functions ###
#####################

# TLV (Type, Length, Value) is the way much of the data is sent an recieved
# The Data below contains the definitions of the Types, their lengths, and what kind
# of data is to be expected (eg strings or ints etc..)
# Also has the _Write_TLV and _Read_TLV functions..

#definitions for the TLVs types being sent from the server..
#The first digit (2 or 4) denotes the FLAP's Chan
%_TLV_IN = (
	2 => {  User_Class		  => 0x01,#!?????
			Signup_Date		 => 0x02,#! doesn't really work for ICQ, set to date of login, 1 sec before normal login date..
			SignOn_Date		 => 0x03,#!
			Unknown00		   => 0x04,#! ??
			Encoded_Message	 => 0x05,#!
			Online_Status	   => 0x06,#!
			Ip_Address		  => 0x0a,#! in 4 byte format..
			Web_Address		 => 0x0b,#!
			Unknown02		   => 0x0c,#! (long like 25 bytes..)
			Unknown03		   => 0x0d,#! ???
			Time_Online		 => 0x0f #!
		},
	4 => {  UIN				 => 0x01,#!
			HTML_Address		=> 0x04,#!
			Server_And_Port	 => 0x05,#!
			Connection_Cookie   => 0x06,#!
			Error_Code		  => 0x08,#!
			Dual_User_Online	=> 0x09,
		},

	);

#definitions for the TLVs types being sent from us to the server..
#The first digit (1 or 2) denotes the FLAP's Chan
%_TLV_OUT = (
	1 => {  UIN				 => 0x01,#!
			Password			=> 0x02,#!
			ClientProfile	   => 0x03,#!
			User_Info		   => 0x05,
			Connection_Cookie   => 0x06,#!
			CountryCode		 => 0x0e,#!
			Language			=> 0x0f,#!
			ClientBuildMinor	=> 0x14,#!
			ClientType		  => 0x16,#!
			ClientVersionMajor  => 0x17,#!
			ClientVersionMinor  => 0x18,#!
			ClientICQNumber	 => 0x19,#!
			ClientBuildMajor	=> 0x1a #!
	},
	2 => {  Status			  => 0x06,#!
			Unknown00		   => 0x08,#!????
			Unknown01		   => 0x0c,#!????
			Unknown00		   => 0x08,#!????
	}
);

#if the TLV is a number, we define the number of bytes to use..(note all numbers are their decimal value, not hex)
# 1000 denotes a "raw" data input, and is encoded differently..
%_TLV_Length_O = (
	1 => {  6	 =>1000,
			20	=>4,
			22	=>2,
			23	=>2,
			24	=>2,
			25	=>2,
			26	=>2
	},
	2 => {  6	 =>4,
			8	 =>2,
	},
);

#This defines the type of data we expect comming in, the codes are as follows..
# 0 or no entry = String
# 1 = Int
# 2 = Raw (obtains the data still as a string of numbers seperated by spaces)
# 3 = IP

%_TLV_Length_I = (
	2 => {  1   =>1,
			2   =>1,
			3   =>1,
			4   =>1,
			5   =>2,
			6   =>1,
			10  =>3,
			15  =>1,
	},
	4 => {  8   =>1,
			6   =>2,
	},
);

# _Write_TLV(Message_Channel, Type_Value, Info_To_Encode)
#
# This creates an packet array ready for sending to the server, containing the given data

sub _Write_TLV {
	my($Chan, $Value, $Infomation) = @_;
	my(@Data);

	$Value = $_TLV_OUT{$Chan}{$Value} if (exists $_TLV_OUT{$Chan}{$Value});

	@Data = _int_to_bytes(2, $Value);

	if ($_TLV_Length_O{$Chan}{$Value} == 1000){
		#get it as an array!
		my @Cookie = split(/ /, $Infomation);
		my $CLength = @Cookie;
		push(@Data, _int_to_bytes(2, $CLength));
		push(@Data, @Cookie);
	}
	elsif (exists $_TLV_Length_O{$Chan}{$Value}){
		#their a number, and need a set byte size..
		push(@Data, _int_to_bytes(2, $_TLV_Length_O{$Chan}{$Value}));
		push(@Data, _int_to_bytes($_TLV_Length_O{$Chan}{$Value}, $Infomation));
	}
	else {
		push(@Data, _int_to_bytes(2, length($Infomation)));
		push(@Data, _str_to_bytes($Infomation));
	}

	return (@Data);
}

# _Read_TLV(Array_to_Read, Message_Channel, Starting_offset_in_array, Array_for_results, Max_number_of_TLVs)
#
# This reads through an packet array picking out and decoding all the TLVs it can find,
# till it reaches the end of the array, or else reaches the Max_Num value (counted in TLVs not bytes..)
# It returns an Hash containing the found types/values and the final of set.

sub _Read_TLV {
	my($Array, $Chan, $Start, $Details, $Max) = @_;
	my($i, $ArrayLength, $DataType, $DataLength, $DataTypeName);

	$ArrayLength = @$Array;

	$Start or $Start = 0;
	$Max or $Max = 100000;

	for ($i = $Start; $i <$ArrayLength;){

		#only get up to the max number of TVLs
		$Max or last;
		$Max--;

		#read in the Data Type/length..
		$DataType   = _bytes_to_int ($Array, $i, 2);
		$DataLength = _bytes_to_int ($Array, $i+2, 2);
		$i += 4;

		#find the name of this data type..
		$DataTypeName = $DataType;
		foreach (keys %{$_TLV_IN{$Chan}}){
			$DataTypeName = $_ if ($_TLV_IN{$Chan}{$_} == $DataType);
		}

		if ($_TLV_Length_I{$Chan}{$DataType} == 2){
			#get it as an array!
			for (my $p=0; $p < $DataLength; $p++){
				$Details->{$DataTypeName} .= $Array->[$i+$p]." ";
			}
			chop $Details->{$DataTypeName};
		}
		elsif ($_TLV_Length_I{$Chan}{$DataType} == 3){
			#get it as IP address
			if ($DataLength != 4){
				print "Argh, This an't an IP!!!\n";
			}
			else {
				$Details->{$DataTypeName} = _bytes_to_int ($Array, $i, 1)."."._bytes_to_int ($Array, $i+1, 1)."."._bytes_to_int ($Array, $i+2, 1)."."._bytes_to_int ($Array, $i+3, 1);
			}
		}
		elsif ($_TLV_Length_I{$Chan}{$DataType} == 1){
			#we're getting a number...
			$Details->{$DataTypeName} = _bytes_to_int ($Array, $i, $DataLength);
		}
		else {
			$Details->{$DataTypeName} = _bytes_to_str ($Array, $i, $DataLength);
		}
		$i +=$DataLength;
	}
	return ($Details, $i);
}


1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

	Net::ICQ2000 - ICQv7 protocol realisation

=head1 SYNOPSIS

  use Net::ICQ2000 ;)

=head1 DESCRIPTION

This module is designed to give perl scripts access to the ICQ network and
the functions provided by it, like SMS




=head1 AUTHOR


Written by Robin Fisher <robin@phase3solutions.com>  UIN 24340914
Some parts/ideas were borrowes from Jeremy Muhlich, Luke Petre and anyone else
who contributed to Net::ICQ.
Slightly modified by Alexander Timoshenko <gonzo@ukrweb.net>

=head1 SEE ALSO

perl(1).

=cut
