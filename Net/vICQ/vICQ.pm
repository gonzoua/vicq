##########################################################
## Based on Net::ICQ2000 module written by Robin Fisher
## $Id: vICQ.pm,v 1.36 2002/08/23 09:19:37 gonzo Exp $
##########################################################


##########################################################
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# See LICENSE for details
##########################################################


package Net::vICQ;


use strict;
no strict 'refs';
use vars qw(
  $VERSION
  $REVISION
  $DEVEL
  %_New_Connection_Nefotiation_Codes
  %_TLV_OUT %_TLV_IN %_TLV_Length_O %_TLV_Length_I %_Srv_Codes
  %_Srv_Decoder %_Cmd_Codes %_Cmd_Encoder %_DC_Decoder %_FileDC_Decoder
  %_ICQ_Versions %_Error_Codes
);

# in releases devel=0
$DEVEL=1;

use Time::Local;
use IO::Socket;
use IO::Select;
use POSIX qw(:errno_h);
use Math::BigInt;

my $Id='$Id: vICQ.pm,v 1.36 2002/08/23 09:19:37 gonzo Exp $';
($REVISION) = $Id=~/ (\d+\.\d+) /;
if ($DEVEL){
	$VERSION='devel';
}else{
	$VERSION='0.05';
}
my $second = 0;


my @client_check_data = split //,"As part of this software beta version Mirabilis is granting a limited access to the ICQ network, servers, directories, listings, information and databases (\"ICQ Services and Information\"). The ICQ Service and Information may databases (\"ICQ Services and Information\"). The ICQ Service and Information may\0";
foreach (@client_check_data)
{
	$_ = ord;
}

sub new
{
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
		_DCSocket => undef,
		_FileSocket => undef,
		_ID => 0,
		_DCs => [],
		_FileDCs => [],
		_DCSelects => [],
		_DCPort => 0,
		_FilePort => 0,
		_ChatPort => 0, # for future :)
		_DCIP => '0.0.0.0',
		_Seq_Num => int(rand(0xFFFF)),
		_Incoming_Queue => [],
		_Outgoing_Queue => [],
		_Connection_Cookie => 0,
		_Incoming_Dir => '',
		_Hooks => {},
		_Connected => 0,
		_LoggedIn => 0,
		_FLAP_Bytes_Left => 0,
		_FLAP_Header_Bytes_Left => 6,
		_FLAP_SubHeader_Bytes_Left => 4,
		_FLAP_Header => [],
		_FLAP_Sub_Header => [],
		_FLAP_In_progress => undef,
		_Mem => 1,
		_Auto_Login => 1, #one means minimum, two means full ICQ logon, 0 means none/developer deals with it..
		_Auto_Login_Contact_List => [],
		_Auto_Login_Visible_List => [],
		_Auto_Login_Invisible_List => [],
		_Sent_Requests => {},
		_Status => 0,
		_Proxy_Host => '',
		_Proxy_Port => '',
		_Proxy_Login => '',
		_Proxy_Password => '',
		_Force_HTTP_Port => '',
		_Proxy_Type => '',
		_Debug => 0,
		_Register => 0,
		_NewUIN => 0,
		_Hide_IP => 0,
		_ErrorStr=> '',
		_ErrorCode=> 0,
		_Away_Message => 'I am away!',
		_NA_Message => 'Not available for this moment',
		_Occupied_Message => 'Occupied!',
		_DND_Message => 'Do Not Disturb!!!!',
		_FFC_Message => 'Let\'s talk!'
	};

	bless($Me, $Package);

	$Me->Connect() if $AutoConnect;

	return $Me;
}

sub SetID
{
	my($Me, $id) = @_;
	$Me->{_ID} = $id;
}

sub Connect
{
	my($Me) = @_;

	return if $Me->{_Connected};

	if(!$Me->{_UIN}) {
		$Me->SetError("Attempted to connect without UIN!");
		return;
	}

	if(!$Me->{_Password}) {
		$Me->SetError("Attempted to connect without Password!");
		return;
	}

	if($Me->{_Proxy_Type} eq 'socks') {
		my $proxy_host = $Me->{_Proxy_Host};
		if($proxy_host eq '') {
			$Me->SetError("No proxy host specified");
			return;
		}
		my $proxy_port = $Me->{_Proxy_Port};
		if($proxy_port eq '') {
			$Me->SetError("No proxy port specified");
			return;
		}
		my $proxy_login = $Me->{_Proxy_Login};
		my $proxy_password = $Me->{_Proxy_Password};
		my $an = ($proxy_login eq '') ? 0 : 1;
		my $socks;
		my $socks_version = 5;
		eval {
			require Net::SOCKS;
		};
		if(!$@) {
			$socks = new Net::SOCKS(socks_addr => $proxy_host,
					socks_port => $proxy_port,
					user_id => $proxy_login,
					user_password => $proxy_password,
					force_nonanonymous => $an,
					protocol_version => $socks_version);

			$Me->{_Socket} = $socks->connect(peer_addr => $Me->{_Server}, peer_port => $Me->{_ServerPort});

			if($socks->param('status_num') != 90) {
				$Me->SetError("SOCKS Connection error: ",Net::SOCKS::status_message($socks->param('status_num')), "\n");
				return;
			}
		} else {
			die "You should install Net::SOCKS package to enable socks proxy support";
		}
	} elsif( $Me->{_Proxy_Type} eq 'https') {

		my $proxy_host = $Me->{_Proxy_Host};
		if($proxy_host eq '') {
			$Me->SetError("No proxy host specified");
			return;
		}

		my $proxy_port = $Me->{_Proxy_Port};
		if($proxy_port eq '') {
			$Me->SetError("No proxy port specified");
			return;
		}

		my $proxy_login = $Me->{_Proxy_Login};
		my $proxy_password = $Me->{_Proxy_Password};
		if ( $Me->{_Force_HTTPS_Port} ) {
			$Me->{_ServerPort} = "443";
		}

		$Me->{_Socket} = IO::Socket::INET->new( Proto => "tcp",
							PeerAddr => $proxy_host,
							PeerPort => $proxy_port);
		if(!$Me->{_Socket}) {
			$Me->SetError("socket error[https proxy]: $@");
			return;
		}

		my $auth = "Proxy-Authorization: Basic " . base64encode("$proxy_login:$proxy_password");
		$Me->{_Socket}->send("CONNECT $Me->{_Server}:$Me->{_ServerPort} HTTP/1.0\n$auth\n\n");
	 } else {
			$Me->{_Socket} = IO::Socket::INET->new(
						Proto	 => "tcp",
						PeerAddr => $Me->{_Server},
						PeerPort => $Me->{_ServerPort});
			if(!$Me->{_Socket}) {
				$Me->SetError("socket error[server]: $@");
				return;
			}
	}

	$Me->{_Select} = IO::Select->new($Me->{_Socket});
	$Me->{_Connected} = 1;
}


sub GetError
{
	my($Me) = @_;
	my $s = $Me->{_ErrorStr};
	$Me->ResetError();
	return $s;
}

sub GetErrorCode
{
	my($Me) = @_;
	my $s = $Me->{_ErrorStr};
	my $c = $Me->{_ErrorCode};
	$Me->ResetError();
	return ($c, $s) if($c);
	return ();
}


sub ResetError
{
	my($Me) = @_;
	$Me->{_ErrorStr} = "";
	$Me->{_ErrorCode} = 0;
}

sub SetError
{
	my($Me,$code,@msgs) = @_;
	$Me->{_ErrorCode} = -1;
	$Me->{_ErrorStr} = join '',@msgs;
}

sub SetErrorCode
{
	my($Me,$code) = @_;
	$Me->{_ErrorCode} = $code;
	$Me->{_ErrorStr} = exists($_Error_Codes{$code}) ?  $_Error_Codes{$code} : 
		"Error code $code";
}

sub InitDCServer
{
	my($Me,$LocalAddr,$LocalPort) = @_;
	$LocalAddr = '0.0.0.0' unless $LocalAddr;
	$LocalPort = undef unless $LocalPort;
	$Me->{_DCSocket} = IO::Socket::INET->new(Listen => 5,
					LocalAddr => $LocalAddr,
					LocalPort => $LocalPort,
					Proto	=> 'tcp',
					Reuse	=> 1,
					Timeout	=> .005);

	if(! defined $Me->{_DCSocket}) {
		$Me->SetError("listen socket error: $!");
		# return $Me;
	} else {
		my $myaddrstruct = $Me->{_DCSocket}->sockname();
		my ($port, $myaddr) = sockaddr_in($myaddrstruct);
		$Me->{_DCIP} = inet_ntoa($myaddr);
		$Me->{_DCPort} = $port;
	}
}

sub InitFileServer
{
	my($Me,$LocalAddr,$LocalPort) = @_;
	$LocalAddr = '0.0.0.0' unless $LocalAddr;
	$LocalPort = undef unless $LocalPort;
	$Me->{_FileSocket} = IO::Socket::INET->new(Listen => 5,
					LocalAddr => $LocalAddr,
					LocalPort => $LocalPort,
					Proto	=> 'tcp',
					Reuse	=> 1,
					Timeout	=> .005);

	if(! defined $Me->{_FileSocket}) {
		$Me->SetError("listen socket error: $!");
		# return $Me;
	} else {
		my $myaddrstruct = $Me->{_FileSocket}->sockname();
		my ($port, $myaddr) = sockaddr_in($myaddrstruct);
		$Me->{_FilePort} = $port;
	}
}


sub Disconnect
{
	my($Me) = @_;

	$Me->{_Connected} or return;

	close($Me->{_Socket});
	$Me->{_Select} = undef;
	$Me->{_Connected} = 0;
	$Me->{_LoggedIn} = 0;
	$Me->{_Incoming_Queue} = [];
	$Me->{_Outgoing_Queue} = [];
	$Me->{_Server} = 'login.icq.com';
	$Me->{_ServerPort} = 5190;
}


sub Send_Keep_Alive
{
	my($Me, $UIN, $Pass) = @_;
	return if (!$Me->{_Connected});
	my($Responce);
	####
	# I didnt find any proper info about keep-alive packets
	# except that its use fifth channel
	# at least it doesnt cause errors - let it be
	####
	$Responce->{Channel_ID} = 5;
	push(@{$Me->{_Outgoing_Queue}}, $Responce);

}

sub Register
{
	my $Me = shift;
	my $uin = 0;
	my $i =0;
	$Me->{_Register} = 1;
	$Me->{_NewUIN} = 0;
	while(($Me->{'_ErrorStr'} eq '') && (!$Me->{_NewUIN}) && $Me->{_Connected})
	{
		$Me->Check_Incoming if $Me->{_Connected};
		$Me->Deal_With_FLAPs if $Me->{_Connected};
		$Me->Send_Outgoing if $Me->{_Connected};
		select(undef, undef, undef, 0.25);
	}
	$Me->{_Register} = 0;
	return $Me->{_NewUIN};
}

sub Set_Login_Details
{
	my($Me, $UIN, $Pass) = @_;

	return if $Me->{_Connected};

	$Me->{_UIN} = $UIN if $UIN;
	$Me->{_Password} = $Pass if $Pass;
}


sub Execute_Once
{
	my ($Me) = @_;

	$Me->Check_Incoming if $Me->{_Connected};
	$Me->Deal_With_FLAPs if $Me->{_Connected};
	$Me->Send_Outgoing if $Me->{_Connected};
	$Me->HandleDC if $Me->{_DCSocket};
	$Me->HandleFileDC if $Me->{_FileSocket};
}

sub Send_Command
{
	my ($Me, $Command, $Details) = @_;
	(exists $_Cmd_Codes{$Command}) or return;

	&{$_Cmd_Encoder{$_Cmd_Codes{$Command}}}($Me, $Details) if (exists $_Cmd_Encoder{$_Cmd_Codes{$Command}});
}

sub Add_Hook
{
	my($Me, $HookType, $HookFunction) = @_;

	$_Srv_Codes{$HookType} or die("Bad Hook type!\n");
	$Me->{_Hooks}{$_Srv_Codes{$HookType}} = $HookFunction;
}


%_ICQ_Versions = (
	4 => 'icq98',
	6 => 'licq',
	7 => 'icq2000',
	8 => 'icq2001');

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

		# another junk filled response (AOL must like using up
		# network resources..)

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

		my $status = $event->{Status} | ($Me->{_Hide_IP} ? 0x10000000 : 0);
		push(@{$Responce->{Data_Load}}, _Write_TLV(2, 'Status', $status));
		push(@{$Responce->{Data_Load}}, _Write_TLV(2, 'ErrorCode', 0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x000c0025));
		# if(!$Me->{_LoggedIn})
		{
			my $ip = inet_aton($Me->{_DCIP});
			my $port = $Me->{_DCPort};
			my $l = length($ip);
			if(!$Me->{_Hide_IP})
			{
				# IP
				push(@{$Responce->{Data_Load}}, _int_to_bytes(4,$ip)); 
				# Port
				push(@{$Responce->{Data_Load}}, _int_to_bytes(4,$port)); 
				# Type of conn
				push(@{$Responce->{Data_Load}}, _int_to_bytes(1,4)); 
				# Version
				push(@{$Responce->{Data_Load}}, _int_to_bytes(2,0x0007)); 
			} else
			{
				push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0)); 
				push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0)); 
				push(@{$Responce->{Data_Load}}, _int_to_bytes(1,0)); 
				push(@{$Responce->{Data_Load}}, _int_to_bytes(2,0));
			}

			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,time())); # ???
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x00000050)); # ???
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x00000003)); # ???
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x04031980));
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,$Me->{_ID}));
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,time()));
			push(@{$Responce->{Data_Load}}, _int_to_bytes(2,0000));
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x012C35FB));
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1,0x3b));
		}
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4,0x00120002)); # TLV
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2,0)); # ???
		push(@{$Me->{_Outgoing_Queue}}, $Responce);

		# send the "Made Change/update command" (really I don't know
		# whta this is for..)
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

		# if this is setting our details, shouldn't we set something?
		# maybe later.. : )

		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 5));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 32));

		foreach (0x09461349,0x4c7f11d1,0x82224445,0x53540000,
				0x09461344, 0x4c7f11d1,0x82224445,0x53540000)
				# 0x97B12751, 0x243C4334, 0xAD22D6AB, 0xF73F1492,
				# 0x2E7A6475, 0xFADF4DC8, 0x886FEA35, 0x95FDB6DF) 
		{
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4,$_));
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

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(3, 4, 0, 0, 0);

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
	# ACK to type-2 messages
	'4:11' => sub {
		my($Me, $event) = @_;
		my($Responce);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(4, 11, 0, 0, 11);
		push(@{$Responce->{Data_Load}}, _str_to_bytes($event->{first_bytes}));
		push(@{$Responce->{Data_Load}}, _uin_to_buin($event->{UIN}));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0003));
		push(@{$Responce->{Data_Load}}, _str_to_bytes($event->{chunk1}));
		push(@{$Responce->{Data_Load}}, _str_to_bytes($event->{chunk2}));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, $event->{type}));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, $event->{flags}));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, $event->{accept_status}));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(3, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_endian_bytes(2,length($event->{msg})+1));
		push(@{$Responce->{Data_Load}}, _str_to_bytes($event->{msg} . "\x0"));
		if($event->{type} == 1)
		{
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x00000000));
			push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0xffffffff));
		}
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
	#Cmd_BOS_Remove_VisibleList
	'9:6' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 6, 0, 0, 6);

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

		foreach (@{$event->{InVisibleList}}) {
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_BOS_Remove_InVisibleList
	'9:8' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 8, 0, 0, 8);

		foreach (@{$event->{InVisibleList}}) {
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	'9:9' => sub {},
	#Cmd_BOS_Add_GenericList
	'9:10' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 10, 0, 0, 10);

		foreach (@{$event->{GenericList}}) {
			push(@{$Responce->{Data_Load}}, _int_to_bytes(1, length($_)));
			push(@{$Responce->{Data_Load}}, _str_to_bytes($_));
		}
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_BOS_Remove_GenericList
	'9:11' => sub {
		my($Me, $event) = @_;
		my($Responce);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(9, 11, 0, 0, 11);

		foreach (@{$event->{GenericList}}) {
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
		my $auth = $event->{Auth};
		push(@TempPacket, _uin_to_buin($uin));
		push(@TempPacket, _int_to_bytes(1,$auth));
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
		if($event->{MessageType} eq 'text') {
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
		} elsif($event->{MessageType} eq 'url') {
			@{$Responce->{Data_Load}} = &_Make_SNAC_Header(4, 6, 0,0,0x00010006);
			my $uin = $event->{uin};
			my $url = $event->{URL};
			my $desc = $event->{Description};
			my $msg = $desc . "\xfe" . $url;
			my $len = length($msg)+9;
			push(@TempPacket, _int_to_bytes(4,0x52995d00));
			push(@TempPacket, _int_to_bytes(4,0x69230000));
			push(@TempPacket, _int_to_bytes(2,0x0004));
			push(@TempPacket, _uin_to_buin($uin));
			push(@TempPacket, _int_to_bytes(2,0x0005)); #TLV
			push(@TempPacket, _int_to_bytes(2,$len)); # TLV
			push(@TempPacket, _int_to_endian_bytes(4,$Me->{_UIN}));
			push(@TempPacket, _int_to_bytes(2,0x0400)); # flags

			$msg = "$msg\x00";
			$len = length($msg);
			push(@TempPacket, _int_to_endian_bytes(2,$len)); # TLV
			push(@TempPacket, _str_to_bytes($msg));
			push(@TempPacket, _int_to_bytes(2,0x0006)); # final TLV
			push(@TempPacket, _int_to_bytes(2,0x0000)); # Final TLV
			push(@{$Responce->{Data_Load}}, @TempPacket);
			push(@{$Me->{_Outgoing_Queue}}, $Responce);

		}
	},
	#Cmd_Get_List
	'19:5' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 5, 0, 0,0x010005);
		push(@TempPacket, _int_to_bytes(4, time()));
		push(@TempPacket, _int_to_bytes(2, 100));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Unk
	'19:17' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 17, 0, 0, 17);
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Init_Contacts
	'19:2' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 2, 0, 0, 2);
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Add_List
	'19:8' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 8, 0, 0,0x020008);
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, 0x00));
		my $uin = $event->{UIN};
		my $nick = $event->{Nick};
		my $cmd = $event->{Command};
		push(@TempPacket, _uin_to_buin($uin)); #encode the ICQ num..
		my $length = length($nick) + 4;
		my $id = rand(0x10000) & 0xffff;
		my $tag = rand(0x10000) & 0xffff;
		push(@TempPacket, _int_to_bytes(2, $id));
		push(@TempPacket, _int_to_bytes(2, $tag));
		push(@TempPacket, _int_to_bytes(2, 0x0));
		push(@TempPacket, _int_to_bytes(2, $length)); # TLV(0)
		push(@TempPacket, _int_to_bytes(1, 1));
		push(@TempPacket, _str_to_bytes("1"));
		push(@TempPacket, _int_to_bytes(1, 0x0));
		push(@TempPacket, _int_to_bytes(1, length($nick)));
		push(@TempPacket, _str_to_bytes($nick));
		# push(@TempPacket, _int_to_bytes(4, 0x00660000));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	# Cmd_Update_Group
	'18:9' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 9, 0, 0,0x09);
		my $cmd = $event->{Name};
		push(@TempPacket, _str_to_lnts("General"));
		push(@TempPacket, _int_to_bytes(2, time() % 0x10000));
		push(@TempPacket, _int_to_bytes(2, 0x0001));
		push(@TempPacket, _int_to_bytes(2, 0x0000));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},

	# Ext_RemoveVisibleList
	'19:10' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(19, 8, 0, 0,0x020008);
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, 0x00));
		my $uin = $event->{UIN};
		push(@TempPacket, _uin_to_buin($uin)); #encode the ICQ num..
		push(@TempPacket, _int_to_bytes(4, 0x00005986));
		push(@TempPacket, _int_to_bytes(4, 0x00020000));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	'23:4' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);
		$Responce->{Channel_ID} = 2;
		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(0x17, 4, 0, 0);
		my $id = 0x9E270000;
		push(@{$Responce->{Data_Load}}, _int_to_bytes(3, 0x000100));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(1, 0x36));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x28000300));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, $id));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, $id));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x0));
		push(@{$Responce->{Data_Load}}, _str_to_lnts($event->{'password'}));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, $id));
		push(@{$Responce->{Data_Load}}, _int_to_bytes(4, 0x00000302));
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
		# $Responce = {};
		# $Responce->{Channel_ID} = 4;
		# push(@{$Me->{_Outgoing_Queue}}, $Responce);
	},
	#Cmd_Srv_Message
	'21:2' => sub {
		my($Me, $event) = @_;
		my($Responce, @TempPacket);

		@{$Responce->{Data_Load}} = &_Make_SNAC_Header(0x15, 2, 0, 0, ($Me->{_Mem}*65536+0x02)); #strange request ID..
		$Me->{_Mem}++;

		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, 0x0001));

		# Argh, Finally figured this bit out!!!
		# this next four packets is the length in little endian
		# and normal!! so work out the packet length first...

		push(@TempPacket, _int_to_endian_bytes(4, $Me->{_UIN})); #encode the ICQ num..

		if ($event->{MessageType} eq "request_offline") {
			push(@TempPacket, _int_to_bytes(2, 0x3c00));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(1, 0));
		} elsif ($event->{MessageType} eq "ack_offline") {
			push(@TempPacket, _int_to_bytes(2, 0x3e00));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(1, 0));
		} elsif ($event->{MessageType} eq "key") {
			print "sending key [$event->{Key}]\n";

			$Me->{_Sent_Requests}{ (($Me->{_Mem}-1)*65536+0x02) } = $event->{Key};

			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(3, 0x9808));

			my $Key = "<key>".$event->{Key}."</key>";

			push(@TempPacket, _int_to_endian_bytes(2, length($Key)+1));
			push(@TempPacket, _str_to_bytes($Key));
			push(@TempPacket, _int_to_bytes(1, 0));

		} elsif ($event->{MessageType} eq "SMS") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_bytes(1, $Me->{_Mem}));

			push(@TempPacket, _int_to_bytes(4, 0x00821400));
			push(@TempPacket, _int_to_bytes(4, 0x01001600));
			push(@TempPacket, _int_to_bytes(17, 0));

			my $TimeString = gmtime();
			if ($TimeString =~ /(\w+) (\w+)\s+(\d+) (\d+:\d+:\d+) (\d+)/) {
				$TimeString = $1.", ".$3." ".$2." ".$5." ".$4." GMT";
			} else {
				print "Unable to encode time...\n";
				return;
			}
			my $text = xml_escape($event->{text});
			my $SMSMessage = "<icq_sms_message><destination>".$event->{SMS_Dest_Number}."</destination><text>".$text."</text>";
			   $SMSMessage .= "<codepage>1252</codepage><senders_UIN>".$Me->{_UIN}."</senders_UIN><senders_name>Robbot</senders_name>";
			   $SMSMessage .= "<delivery_receipt>Yes</delivery_receipt><time>$TimeString</time></icq_sms_message>";

			my $SMSLength = length($SMSMessage)+1;

			push(@TempPacket, _int_to_bytes(2, $SMSLength));
			push(@TempPacket, _str_to_bytes($SMSMessage));
			push(@TempPacket, _int_to_bytes(1, 0)); #null end..

		} elsif ($event->{MessageType} eq "user_short_info_request") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(2, 0xba04));
			push(@TempPacket, _int_to_endian_bytes(4, $event->{TargetUIN})); #encode the ICQ num..

		} elsif ($event->{MessageType} eq "Set_Permissions") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(2, 0x2404));
			my $auth = $event->{_auth} ? 0 : 1;
			my $web = $event->{_web};
			push(@TempPacket, _int_to_endian_bytes(1, $auth)); #encode the ICQ num..
			push(@TempPacket, _int_to_endian_bytes(1, $web));
			push(@TempPacket, _int_to_bytes(2, 0x0100));

		} elsif ($event->{MessageType} eq "Get_WP_Info") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			$Me->{_Requests}->{($Me->{_Mem}-1)*65536+0x02} = $event->{TargetUIN};
			push(@TempPacket, _int_to_bytes(2, 0xb204));
			push(@TempPacket, _int_to_endian_bytes(4, $event->{TargetUIN})); #encode the ICQ num..

		} elsif ($event->{MessageType} eq "Random_Search") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			$Me->{_Requests}->{($Me->{_Mem}-1)*65536+0x02} = $event->{TargetUIN};
			push(@TempPacket, _int_to_bytes(2, 0x4e07));
			push(@TempPacket, _int_to_endian_bytes(1, $event->{TargetGroup}));
			push(@TempPacket, _int_to_endian_bytes(1, 0));

		} elsif ($event->{MessageType} eq "Set_Group") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			$Me->{_Requests}->{($Me->{_Mem}-1)*65536+0x02} = $event->{TargetUIN};
			push(@TempPacket, _int_to_bytes(2, 0x5807));
			push(@TempPacket, _int_to_endian_bytes(1, $event->{TargetGroup}));
			push(@TempPacket, _int_to_bytes(4, 0x00000003));
			push(@TempPacket, _int_to_bytes(4, 0x20000000));
			push(@TempPacket, _int_to_bytes(4, 0x00000000));
			push(@TempPacket, _int_to_bytes(4, 0x00000000));
			push(@TempPacket, _int_to_bytes(4, 0x00040800));
			push(@TempPacket, _int_to_bytes(4, 0x00000000));
			push(@TempPacket, _int_to_bytes(4, 0x00005000));
			push(@TempPacket, _int_to_bytes(4, 0x00000300));
			push(@TempPacket, _int_to_bytes(2, 0x0000));

		} elsif ($event->{MessageType} eq "Change_Password") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			$Me->{_Requests}->{($Me->{_Mem}-1)*65536+0x02} = $event->{TargetUIN};
			push(@TempPacket, _int_to_bytes(2, 0x2e04));
			push(@TempPacket, _str_to_lnts($event->{Password}));

		} elsif ($event->{MessageType} eq "Self_Info_Request") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(2, 0xd004));
			push(@TempPacket, _int_to_endian_bytes(4, $Me->{_UIN})); #encode the ICQ num..
			# print ">> $Me->{_UIN}\n";

		} elsif ($event->{MessageType} eq "Set_Main_WP_Info") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(2, 0xea03));
			push(@TempPacket, _str_to_lnts($event->{_nickname}));
			push(@TempPacket, _str_to_lnts($event->{_firstname}));
			push(@TempPacket, _str_to_lnts($event->{_lastname}));
			push(@TempPacket, _str_to_lnts($event->{_email}));
			push(@TempPacket, _str_to_lnts($event->{_city}));
			push(@TempPacket, _str_to_lnts($event->{_state}));
			push(@TempPacket, _str_to_lnts($event->{_phone}));
			push(@TempPacket, _str_to_lnts($event->{_fax}));
			push(@TempPacket, _str_to_lnts($event->{_street}));
			push(@TempPacket, _str_to_lnts($event->{_cellular}));
			push(@TempPacket, _str_to_lnts($event->{_zip}));
			push(@TempPacket, _int_to_endian_bytes(2,$event->{_country}));
			push(@TempPacket, _int_to_bytes(1,$event->{_GMT}));
			push(@TempPacket, _int_to_bytes(1,0));

		} elsif ($event->{MessageType} eq "User_Info_Request") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(2, 0xb204));
			push(@TempPacket, _int_to_endian_bytes(4, $event->{TargetUIN})); #encode the ICQ num..

		} elsif ($event->{MessageType} eq "WP_Full_Request") {
			push(@TempPacket, _int_to_bytes(2, 0xd007));
			push(@TempPacket, _int_to_endian_bytes(2, $Me->{_Mem}));
			push(@TempPacket, _int_to_bytes(2, 0x3305));

		#max 20 on everything unless noted
		#first
			push(@TempPacket, _int_to_bytes(1, length($event->{_firstname})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_firstname}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#last
			push(@TempPacket, _int_to_bytes(1, length($event->{_lastname})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_lastname}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#nick
			push(@TempPacket, _int_to_bytes(1, length($event->{_nickname})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_nickname}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#email (max 25)
			push(@TempPacket, _int_to_bytes(1, length($event->{_email})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_email}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#Min age
			push(@TempPacket, _int_to_bytes(1, $event->{_min_age}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#Max age
			push(@TempPacket, _int_to_bytes(1, $event->{_max_age}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#Sex (0,1,2)
			push(@TempPacket, _int_to_bytes(1, $event->{_sex}));
		#Language (0...see table)
			push(@TempPacket, _int_to_bytes(1, $event->{_language}));
		#city
			push(@TempPacket, _int_to_bytes(1, length($event->{_city})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_city}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#state (max 3)
			push(@TempPacket, _int_to_bytes(1, length($event->{_state})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_state}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#country (see table)
			push(@TempPacket, _int_to_bytes(1, $event->{_country}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#company-name
			push(@TempPacket, _int_to_bytes(1, length($event->{_company_name})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_company_name}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#company-department
			push(@TempPacket, _int_to_bytes(1, length($event->{_company_dep})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_company_dep}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#company-position
			push(@TempPacket, _int_to_bytes(1, length($event->{_company_pos})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_company_pos}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#company-occupation
			push(@TempPacket, _int_to_bytes(1, $event->{_company_occ}));
		#past information category
			push(@TempPacket, _int_to_bytes(2, $event->{_past_info_cat}));
		#past information
			push(@TempPacket, _int_to_bytes(1, length($event->{_past_info_desc})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_past_info_desc}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#interests category (see table)
			push(@TempPacket, _int_to_bytes(1, $event->{_interests_cat}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#interests specific - comma, delim
			push(@TempPacket, _int_to_bytes(1, length($event->{_interests_desc})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_interests_desc}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#organization
			push(@TempPacket, _int_to_bytes(1, $event->{_org_cat}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#organization specific - comma, delim
			push(@TempPacket, _int_to_bytes(1, length($event->{_org_desc})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_org_desc}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#homepage category
			push(@TempPacket, _int_to_bytes(2, $event->{_homepage_cat}));
		#homepage
			push(@TempPacket, _int_to_bytes(1, length($event->{_homepage})+1));
			push(@TempPacket, _int_to_bytes(1, 0x00));
			push(@TempPacket, _str_to_bytes($event->{_homepage}));
			push(@TempPacket, _int_to_bytes(1, 0x00));
		#Only online users (0 or 1)
			push(@TempPacket, _int_to_bytes(1, $event->{_online_only}));

		}

		#NOW work out that length thingy (what a crappy place for it!!!)
		push(@{$Responce->{Data_Load}}, _int_to_bytes(2, $#TempPacket + 3));
		push(@{$Responce->{Data_Load}}, _int_to_endian_bytes(2, $#TempPacket + 1));
		push(@{$Responce->{Data_Load}}, @TempPacket);
		push(@{$Me->{_Outgoing_Queue}}, $Responce);

	}
);

%_FileDC_Decoder = (
	'File:0' => sub {
		my @Response;
		my ($Me, $event) = @_;
		my $connection = $event->{Connection};
		my $i = 7;
		my $files = _endian_bytes_to_int($event->{Data_Load}, $i ,4);
		$i += 4;
		my $length = _endian_bytes_to_int($event->{Data_Load}, $i ,4);
		$i += 4;
		my $speed = _endian_bytes_to_int($event->{Data_Load}, $i ,4);
		$i += 4;
		my $name = _bytes_to_lnts($event->{Data_Load}, $i);
		$connection->{FileNum} = 0;
		push @Response,_int_to_endian_bytes(2, 11); # length
		push @Response,_int_to_endian_bytes(1, 0x1); # id
		push @Response,_int_to_endian_bytes(4, 0x00000064); # speed
		push @Response,_str_to_lnts("xxx"); # Nick
		push @{$connection->{ToSend}},@Response;
	},
	'File:5' => sub {
		# Change speed, just ignore this
	},
	'File:6' => sub {
		# Got Data!
		my ($Me, $event) = @_;
		my $dir = $Me->{_Incoming_Dir};
		if($dir ne '') {
			$dir .= '/';
		}
		my $connection = $event->{Connection};
		my $i = 0;
		my $size = _endian_bytes_to_int($event->{Data_Load}, $i, 2);
		$size--;
		my $data = _bytes_to_str($event->{Data_Load}, 1, $size);
		open FILE, ">> $dir" . "$connection->{FileName}";
		binmode FILE;
		print FILE $data;
		close FILE;
	},
	'File:2' => sub {
		my @Response;
		my $Refined;
		my ($Me, $event) = @_;
		my $connection = $event->{Connection};
		my $i = 4;
		my $name = _bytes_to_lnts($event->{Data_Load}, $i);
		$i += length($name) + 3;
		$connection->{FileName} = $name;
		$connection->{FileNum}++;
		my $text = _bytes_to_lnts($event->{Data_Load}, $i);
		$i += length($text) + 3;
		my $size = _endian_bytes_to_int($event->{Data_Load}, $i ,4);
		# TODO Make resume...
		my $num = $connection->{FileNum};

		$Refined->{MessageType} = "file";
		$Refined->{Connection} = $connection;
		$Refined->{Sender} = $connection->{UIN};

		push @Response,_int_to_endian_bytes(2, 17); # length
		push @Response,_int_to_endian_bytes(1, 0x3); # id
		push @Response,_int_to_endian_bytes(4, 0x00000000); # skip size
		push @Response,_int_to_endian_bytes(4, 0x00000000); # unkn
		push @Response,_int_to_endian_bytes(4, 0x00000064); # speed
		push @Response,_int_to_endian_bytes(4, $num); # unknown
		push @{$connection->{ToSend}},@Response;
		return $Refined;
	}
);

%_DC_Decoder = (
	'DC:2030' => sub {
		my ($Me, $event) = @_;
		my @Ack = ();
		my $skipack = 0;
		my $seqnum = _endian_bytes_to_int($event->{Data_Load},11 ,2); # seqn
		my $type = _endian_bytes_to_int($event->{Data_Load},25 ,1); # flags
		my $flags = _endian_bytes_to_int($event->{Data_Load},26 ,1); # flags
		my $connection = $event->{Connection};
		my $Refined;
		my $msg = '';
		$Refined->{MessageType} = "DC:$type";
		if($type == 1) {
			my $i = 31;
			my $DataLength = _endian_bytes_to_int($event->{Data_Load}, $i ,2);
			$i+=2;
			my $text = _bytes_to_str($event->{Data_Load},$i , $DataLength);
			$Refined->{text} = $text;
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "text_message";

		} elsif($type == 2) {
			my $i = 31;
			$Refined->{Reason} = _bytes_to_lnts($event->{Data_Load},$i);
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "chat";

		} elsif($type == 3) {
			my $i = 31;
			my $description = _bytes_to_lnts($event->{Data_Load},$i);
			$i += length($description) + 3;
			$i+=4;
			my $files = _bytes_to_lnts($event->{Data_Load},$i);
			$i += length($files) + 3;
			my $size = _endian_bytes_to_int($event->{Data_Load}, $i ,4);
			($Refined->{Description},$Refined->{Files},$Refined->{Size}) = ($description, $files, $size);
			$connection->{type} = $type;
			$connection->{flags} = $flags;
			$connection->{seqnum} = $seqnum;
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "files";
			$Refined->{Connection} = $connection;
			$skipack = 1;

			# This is generic decline ack... For future :)
			# @Ack = BuildGenericAck($type,$flags,$seqnum,1);
			# push(@Ack, _str_to_lnts("No files!"));
			# push(@Ack, _int_to_endian_bytes(4, 0xffffffff));
			# push(@Ack, _int_to_endian_bytes(3, 0x000100));
			# push(@Ack, _int_to_endian_bytes(4, 0xffffffff));
			# push(@Ack, _int_to_endian_bytes(4, 0xffffffff));

			# Accept ack
			# my $port = $Me->{_FilePort};
			# @Ack = BuildGenericAck($type,$flags,$seqnum);
			# push(@Ack, _int_to_endian_bytes(1, 0x01));
			# push(@Ack, _int_to_bytes(4, $port));
			# push(@Ack, _int_to_endian_bytes(2, 0x0000));
			# push(@Ack, _str_to_lnts(""));
			# push(@Ack, _int_to_bytes(4, 0x12345678));
			# push(@Ack, _int_to_endian_bytes(4, $port));

		} elsif($type == 4) {
			my $i = 31;
			my $DataLength = _endian_bytes_to_int($event->{Data_Load}, $i ,2);
			$i+=2;
			my $text = _bytes_to_str($event->{Data_Load},$i , $DataLength);
			($Refined->{Description},$Refined->{URL}) = split /\xfe/,$text;
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "URL";

		} elsif($type == 19) {
			my $i = 31;
			my $DataLength = _endian_bytes_to_int($event->{Data_Load}, $i ,2);
			$i+=2;
			my $text = _bytes_to_str($event->{Data_Load},$i , $DataLength);
			# ($Refined->{Description},$Refined->{URL}) = split /\xfe/,$text;
			my ($count,@contacts) = split /\xfe/,$text;
			pop @contacts;
			$Refined->{Count} = $count;
			$Refined->{Contacts} = \@contacts;
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "contacts";

		} elsif($type == 26) {
			my $i = 97;
			my $DataLength = _endian_bytes_to_int($event->{Data_Load}, $i ,4);
			$i+=4;
			my $text = _bytes_to_str($event->{Data_Load},$i , $DataLength);
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "contacts_request";
			$Refined->{Reason} = $text;

		} elsif($type == 0xE8) {
			# TODO Make normal messaging
			$msg = $Me->{_Away_Message}; # 'I am away!';
			$Refined->{MessageType} = "dummy";

		} elsif($type == 0xE9) {
			# TODO Make normal messaging
			$msg = $Me->{_Occupied_Message}; # 'Occupied!';
			$Refined->{MessageType} = "dummy";

		} elsif($type == 0xEA) {
			# TODO Make normal messaging
			$msg = $Me->{_NA_Message}; # 'Not available for this moment';
			$Refined->{MessageType} = "dummy";

		} elsif($type == 0xEB) {
			# TODO Make normal messaging
			$msg = $Me->{_DND_Message}; # 'Do Not Disturb!!!!';
			$Refined->{MessageType} = "dummy";

		} elsif($type == 0xEC) {
			# TODO Make normal messaging
			$msg = $Me->{_FFC_Message}; # 'Let\'s talk!';
			$Refined->{MessageType} = "dummy";

		} else {
			$Refined->{Sender} = $connection->{UIN};
			$Refined->{MessageType} = "DC:$type";
		}

		if(!@Ack) {
			@Ack = BuildGenericAck($type,$flags,$seqnum);
			push(@Ack, _str_to_lnts($msg));
			push(@Ack, _int_to_endian_bytes(4, 0x00000000));
			push(@Ack, _int_to_endian_bytes(4, 0xffffffff));
		}

		@Ack = Encrypt(\@Ack);
		push @{$connection->{ToSend}},@Ack unless $skipack;
		return $Refined;
	},
	'DC:2000' => sub {
			my $Refined;
			$Refined->{MessageType} = "dummy";
			return $Refined;
			# Cancel command
			# dummy :(
	}
);

%_Srv_Decoder = (
	#Srv_GSC_Ready
	'1:3' => sub {
		my ($Me, $event) = @_;
		#nothing interesting to get from SNAC..

		if ($Me->{_Auto_Login}) {
			$Me->Send_Command("Cmd_GSC_ICQInform");
		}
		return;
	},
	#Srv_GSC_Rate_Info
	"1:7" => sub {
		my ($Me, $event) = @_;
		#my ($Refined);

		if ($Me->{_Auto_Login} > 1) {
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
		#(tells us all the possible commands?..)
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

		if ($Me->{_Auto_Login}) {
			if ($Me->{_Auto_Login} == 1) {
				my ($details);

				$Me->Send_Command("Cmd_Mes_Add_ICBM_Param");
				$Me->Send_Command("Cmd_LS_Set_User_Info");
				$details->{Status} = $Me->{_Status};
				if(($Me->{_Status} & 0x100 ) && !$Me->{_no_lists}) {
					$Me->Send_Command("Cmd_BOS_Add_VisibleList", 
						{ VisibleList=> $Me->{_Auto_Login_Visible_List}});
				}
				if(!$Me->{_no_lists}) {
					$Me->Send_Command("Cmd_CTL_UploadList", 
						{ContactList=> $Me->{_Auto_Login_Contact_List}});
				}
				$Me->Send_Command("Cmd_GSC_Set_Status", $details);
				$Me->Send_Command("Cmd_GSC_Client_Ready");
				if(!($Me->{_Status} & 0x100 ) && !$Me->{_no_lists}) {
					$Me->Send_Command("Cmd_BOS_Add_InVisibleList", 
						{ InVisibleList => $Me->{_Auto_Login_Invisible_List}});
				}
				$Me->Send_Command("Cmd_Srv_Message", 
					{MessageType => "request_offline"}) 
				unless $Me->{_no_offline_messages};
				$Me->{_LoggedIn} = 1;
			} else {
				$Me->Send_Command("Cmd_GSC_Reqest_Rate_Info");
			}
		}
		return ($Refined);
	},
	#Srv_LS_Rights_Response
	'2:3' => sub {
		my ($Me, $event) = @_;
		my ($Refined);

		#no idea what to do with this data..
		#$event->{Data_Load}
		return ($Refined);
	},
	#Srv_BLM_Rights_Response
	'3:3' => sub {
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

		$Refined->{Sender} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);$i += $DataLength + 4;

		($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, _bytes_to_int($event->{Data_Load}, $i-4, 4));

		my $st = 0;
		$st = $Refined->{Status} if exists $Refined->{Status};
		$st &= 0xffff;
	# my $hexst = sprintf '%04x',$st;
		$Refined->{MessageType} = "status_change";
		$Refined->{Status} = $st;
		# my $inv = 0;
		# if($st & 0x100)
		# {
			# $hexst = sprintf '%04x',$st & ~0x100;
			# $inv = 1;
		# }
		# if(exists $_r_Status_Codes{$hexst})
		# {
			# $Refined->{Status} = $_r_Status_Codes{$hexst};
			# if($inv)
			# {
				# $Refined->{Status} .= "[inv]";
			# }
		# } else
		# {
			# print ">> Unknown status: $hexst, please report this bug to gonzo\@ukrweb.net <<\n";
			# $Refined->{Status} = 'Online';
		# }
		if($Refined->{'LANInfo'}) {
			my @data = split //,$Refined->{'LANInfo'};
			foreach (@data)
			{
				$_ = ord;
			}
			$Refined->{'LAN_IP'} = inet_ntoa(_bytes_to_str(\@data,0,4));
			$Refined->{'LAN_Port'} = _bytes_to_int(\@data,4,4);
			$Refined->{'ConnectionType'} = _bytes_to_int(\@data,8,1);
			$Refined->{'ICQ_Version'} = _bytes_to_int(\@data,9,2);
			undef $Refined->{'LANInfo'};
		}
		return ($Refined);
	},
	#Srv_BLM_Contact_Offline
	'3:12' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $DataLength, $i);

		$i = 10;
		$DataLength = ${$event->{Data_Load}}[$i];$i++;

		$Refined->{MessageType} = 'status_change';
		$Refined->{Sender} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);$i += $DataLength + 4;
		$Refined->{Status} = 0xffff;

		($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, _bytes_to_int($event->{Data_Load}, $i-4, 4));
		return ($Refined);
	},
	#Srv_Mes_Rights_Response
	'4:5' => sub {
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

		print "Incoming..\n" if $Me->{_Debug};
		_print_packet($event->{Data_Load}, ()) if $Me->{_Debug};

		$i = 19;
		my $fb = _bytes_to_str($event->{Data_Load}, 10, 10);

		$Refined->{SenderType} = $event->{Data_Load}->[$i];$i++;
		$DataLength = ${$event->{Data_Load}}[$i];$i++;
		$Refined->{Sender} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);$i += $DataLength + 4;

		$Refined->{MessageType} = "unknown:" . $Refined->{SenderType};
		# ($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, _bytes_to_int($event->{Data_Load}, $i-4, 4));
		($Refined, $i) = _Read_TLV($event->{Data_Load}, 2, $i, $Refined, 10000);
		print "==> SenderType = '$Refined->{SenderType}'\n" if $Me->{_Debug};
		if(($Refined->{SenderType} == 1))
		{
			$Refined->{Message_Encoding} = _bytes_to_int($event->{Data_Load}, 18, 2); # $i+=2;
			print "==> Message_Encoding = $Refined->{Message_Encoding}\n" if $Me->{_Debug};
			if ($Refined->{Encoded_Message} && $Refined->{Message_Encoding} == 2){
				print "Encoded_Message: " . $Refined->{Encoded_Message} . "\n" if $Me->{_Debug};


				#this is a weird ass message, so decode it..
				my @Encoded_Message = split(/ /, $Refined->{Encoded_Message});
				undef $Refined->{Encoded_Message};
				$Refined->{Sender} = _endian_bytes_to_int(\@Encoded_Message,0,4);
				my $subtype = _bytes_to_int(\@Encoded_Message,4,1);
				my $flags = _bytes_to_int(\@Encoded_Message,5,1);
				my $DataLength = _endian_bytes_to_int(\@Encoded_Message,6,2);
				my $data = _bytes_to_str(\@Encoded_Message,8,$DataLength);
				$Refined->{MessageType} .= ":$subtype";
				if($subtype == 0x0E) {
					$Refined->{MessageType} = 'email_message';
					my ($name,$junk1,$junk2,$email,$junk3,$text) = split /\xfe/,$data;
					$Refined->{Name} = $name;
					$Refined->{Email} = $email;
					$Refined->{Text} = $text;
				} else {
					$Refined->{TaggedDataString} = _bytes_to_str(\@Encoded_Message, 0x32, _endian_bytes_to_int(\@Encoded_Message, 0x2f, 2));
	
					_Decode_Tagged_Text($Refined->{TaggedDataString}, $Refined);
				}
				return ($Refined);
			} elsif ($Refined->{Encoded_MessageOld} && $Refined->{Message_Encoding} == 1) {
#				print "Encoded_MessageOld = " . $Refined->{Encoded_MessageOld} . "\n";

				my @Encoded_Message = split(/ /, $Refined->{Encoded_MessageOld});
				my $DataLength = $#Encoded_Message + 1 - 12;
#				print "DataLength = $DataLength \n";

				$Refined->{MessageType} = "text_message";
				$Refined->{text} = _bytes_to_str(\@Encoded_Message, 13, $DataLength);

#				$Refined->{text} = _bytes_to_str($event->{Data_Load}, 86, $DataLength);

				return ($Refined);
			} elsif ($Refined->{Encoded_Message} && $Refined->{Message_Encoding} == 4) {
				my @Encoded_Message = split(/ /, $Refined->{Encoded_Message});
				my $DataLength = _endian_bytes_to_int(\@Encoded_Message,6,2);
#				my $data = _bytes_to_str(\@Encoded_Message,8,$DataLength);

				$Refined->{MessageType} = "text_message";
				$Refined->{text} = _bytes_to_str(\@Encoded_Message, 8, $DataLength);
				return ($Refined);
			}

# =========
			if ($Refined->{Message_Encoding} == 2){

				#normal text message..
				$Refined->{MessageType} = "text_message";
	
				$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
				$i += 15;
	
				$DataLength -= 13;
	
				$Refined->{text} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);
				$Refined->{text} =~ s/\r\n/\n/g;
			} elsif ($Refined->{Message_Encoding} == 5) {
				$DataLength = _bytes_to_int($event->{Data_Load}, $i, 2);
				$i+=2;
				$i+=4;
				my $type = ord(_bytes_to_str($event->{Data_Load}, $i, 1));
			 	# print "++> $type\n";
				$i++;
				my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
				my @bytes = _str_to_bytes($data);
				# print ">> [$type] @bytes <<\n";
				# print "$bytes[2]\n";
				if($type == 12) {
					# You have been added
					$Refined->{MessageType} = "add_message";
				} elsif($type == 6) {
					# Auth request!
					$i++;
					my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength-4);
					my($nick,$fname,$lname,$email,$xxx,$reason);
					($nick,$fname,$lname,$email,$xxx,$reason) = split /\xfe/,$data;
					$Refined->{nick} = $nick;
					$Refined->{first_name} = $fname;
					$Refined->{last_name} = $lname;
					$Refined->{email} = $email;
					$Refined->{reason} = $reason;
					$Refined->{MessageType} = "auth_request";
	
				} elsif($type == 1) {
					# ????
					$Refined->{MessageType} = "text_message";
					my $DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					$i += 2;
					$Refined->{text} = _bytes_to_str($event->{Data_Load}, $i, $DataLength);
					$Refined->{text} =~ s/\r\n/\n/g;
	
				} elsif($type == 4) {
					# URL
					$Refined->{MessageType} = "URL";
					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					($Refined->{Description},$Refined->{URL}) = split /\xfe/,$data;
				} elsif($type == 26) {
					# Contact request
					$i += 3;
					my $type = _bytes_to_int($event->{Data_Load}, $i, 2);
					$i += 21;
					my $length = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
					$i += 4;
					my $s = _bytes_to_str($event->{Data_Load},$i,$length);
					$i += $length;
					$i += 19;
					$length = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
					$i += 4;
					my $reason = _bytes_to_str($event->{Data_Load},$i,$length);
					$Refined->{MessageType} = "contacts_request";
					$Refined->{Reason} = $reason;
	
				} elsif($type == 19) {
					# Auth request!
					$i+=2;
					my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
					my ($contactcount,@contacts) = split /\xfe/,$data;
					# print "Got $contactcount contacts!\n";
					# $j = 0;
					# while($ <= $#contacts)
					# {
					#	 print $contacts[$i]. " " . $contacts[$i+1] . "\n";
					#	 $i+=2;
					# }
					$Refined->{MessageType} = "contacts";
					$Refined->{Count} = $contactcount;
					$Refined->{Contacts} = \@contacts;
				}
			}
		}
		elsif($Refined->{SenderType} == 2) 
		{
			$i += 4;
			my $flag = _bytes_to_int($event->{Data_Load}, $i, 2);
			$i += 2;
			$i += 24;
			while($i<@{$event->{Data_Load}})
			{
				my $tlv_type = _bytes_to_int($event->{Data_Load}, $i, 2);
				$i += 2;
				my $tlv_length = _bytes_to_int($event->{Data_Load}, $i, 2);
				$i += 2;
				my $tlvdata = _bytes_to_str($event->{Data_Load}, $i, $tlv_length);
				# print "?? $tlv_type : $tlv_length ??\n";
				my $oldi = $i;
				my $reply = "";
				# Let's ignore misc info packets
				$Refined->{MessageType} = "dummy";
				
				if($tlv_type == 0x2711)
				{
					my $len = _endian_bytes_to_int($event->{Data_Load}, $i, 2);
					$event->{Data_Load}[$i+2+24] = 0;
					$event->{Data_Load}[$i+2] = 7; # Protocol version
					my $chunk1 = _bytes_to_str($event->{Data_Load}, $i, $len+2);
					$i += 2+$len; #ignore files part
					$len = _endian_bytes_to_int($event->{Data_Load}, $i, 2);
					if($len == 0x0e)
					{
						my $chunk2 = _bytes_to_str($event->{Data_Load}, $i, $len+2);
						$i += 2+$len; #ignoring chunk 2
					
						my $type = _bytes_to_int($event->{Data_Load}, $i, 1); 
						$i++;
						my $flags = _bytes_to_int($event->{Data_Load}, $i, 1); 
						$i++;
						my $status_code = _bytes_to_int($event->{Data_Load}, $i, 2); 
						$i += 2; 
						$i += 2; # priority
						$len = _endian_bytes_to_int($event->{Data_Load}, $i, 2);
						$i += 2;
						my $msg = _bytes_to_str($event->{Data_Load}, $i, $len);
						$i += $len;
						$Refined->{MessageType} = $type;
						# print "Message: $type:$flags $status_code\n\n";
						if($type == 0) # Strange message
						{
							$Refined->{MessageType} = "dummy"; # ignore it
						}
						if($type == 1) # text message
						{
							$Refined->{MessageType} = "text_message";
							$Refined->{text} = $msg;
						} elsif($type == 2) # Chat
						{
							$Refined->{MessageType} = "chat";
							$Refined->{Reason} = $msg;
						} elsif($type == 3) # File ops
						{
							$Refined->{MessageType} = "file_request";
							# print "debug:: $msg\n\n";
						} elsif($type == 4) # URL
						{
							$Refined->{MessageType} = "URL";
							($Refined->{Description},$Refined->{URL}) = split /\xfe/,$msg;
				
						} elsif($type == 6) # Auth request
						{
							my($nick,$fname,$lname,$email,$xxx,$reason) = split /\xfe/,$msg;;
							$Refined->{nick} = $nick;
							$Refined->{first_name} = $fname;
							$Refined->{last_name} = $lname;
							$Refined->{email} = $email;
							$Refined->{reason} = $reason;
							$Refined->{MessageType} = "auth_request";
						} elsif($type == 0xC) # You have been added
						{
							$Refined->{MessageType} = "add_message";
						} elsif($type == 0xD) # WEB-pager
						{
							$Refined->{MessageType} = "web_message";
							my ($name,$junk,$junk2,$email,$junk3,$ip,$text) = split /\xfe/,$msg;
							$Refined->{Name} = $name;
							$Refined->{Email} = $email;
							$Refined->{Text} = $text;
							$Refined->{SenderIP} = $ip;
						} elsif($type == 0xE) # Email
						{
							$Refined->{MessageType} = 'email_message';
							my ($name,$junk,$junk2,$email,$junk3,$text) = split /\xfe/,$msg;
							$Refined->{Name} = $name;
							$Refined->{Email} = $email;
							$Refined->{Text} = $text;
						} elsif($type == 0x13) # Contacts
						{
							my ($contactcount,@contacts) = split /\xfe/,$msg;
							$Refined->{MessageType} = "contacts";
							$Refined->{Count} = $contactcount;
							$Refined->{Contacts} = \@contacts;
						} elsif($type == 0x1A) # Contacts req || GCard
						{
							my $id = _endian_bytes_to_int($event->{Data_Load}, $i, 1);
							$i++;
							if($id == 57) # Contacts request
							{
								$i += 0x3e;
								my $len = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
								$i += 4;
								$Refined->{MessageType} = "contacts_request";
								$Refined->{Reason} = _bytes_to_str($event->{Data_Load}, $i, $len);
							} else { # Greeting card
								$i += 19;
								my ($junk, $version, $theme, $pre_title, $design);
								my ( $title, $recipient, $text, $sender, $url);
								($junk, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								$i += 3;
								my $minor = _endian_bytes_to_int($event->{Data_Load}, $i, 2);
								$i += 2;
								my $major = _endian_bytes_to_int($event->{Data_Load}, $i, 2);
								$i += 2;
								$version = "$major.$minor";
								if($version eq "1.2")
								{
									$i += 12;
								} else
								{
									$i += 4;
								}
								($version, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($theme, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($pre_title, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($design, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($title, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($recipient, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($text, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								($sender, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								$i += 4;
								if($version eq "1.2")
								{
									($url, $i) = _bytes_to_ds($event->{Data_Load}, $i);
								}
								$Refined->{MessageType} = "greeting_card";
								$Refined->{version} = $version;
								$Refined->{theme} = $theme;
								$Refined->{pre_title} = $pre_title;
								$Refined->{title} = $title;
								$Refined->{recipient} = $recipient;
								$Refined->{sender} = $sender;
								$Refined->{text} = $text;
								$Refined->{url} = $url;
						
							
								
							}
						} elsif($type == 0xE8) {
							# TODO Make normal messaging
							$reply = $Me->{_Away_Message}; # 'I am away!';
							$Refined->{MessageType} = "dummy";
				
						} elsif($type == 0xE9) {
							# TODO Make normal messaging
							$reply = $Me->{_Occupied_Message}; # 'Occupied!';
							$Refined->{MessageType} = "dummy";
	
						} elsif($type == 0xEA) {
							# TODO Make normal messaging
							$reply = $Me->{_NA_Message}; # 'Not available for this moment';
							$Refined->{MessageType} = "dummy";
			
						} elsif($type == 0xEB) {
							# TODO Make normal messaging
							$reply = $Me->{_DND_Message}; # 'Do Not Disturb!!!!';
							$Refined->{MessageType} = "dummy";
				
						} elsif($type == 0xEC) {
							# TODO Make normal messaging
							$reply = $Me->{_FFC_Message}; # 'Let\'s talk!';
							$Refined->{MessageType} = "dummy";

						} 
						$Me->Send_Command("Cmd_Type2_Ack", {
							type => $type,
							flags => $flags,
							chunk1 => $chunk1,
							chunk2 => $chunk2,
							first_bytes => $fb,
							UIN => $Refined->{Sender},
							msg => $reply
						});
					} else
					{
						$Refined->{MessageType} = "dummy";
					}
				}
				$i = $oldi + $tlv_length; 
			}
		}
		elsif($Refined->{SenderType} == 4) 
		{
			$i += 8; # UIN
			my $type = _bytes_to_int($event->{Data_Load}, $i , 1); $i++;
			my $flags = _bytes_to_int($event->{Data_Load}, $i , 1); $i++;
			my $len = _endian_bytes_to_int($event->{Data_Load}, $i , 2); $i+=2;
			my $msg = _bytes_to_str($event->{Data_Load}, $i , $len);
			# print ">>> $type:$flags:$len:$msg \n\n";
			if($type == 0) # Strange message
			{
				$Refined->{MessageType} = "dummy"; # ignore it
			}
			if($type == 1) # text message
			{
				$Refined->{MessageType} = "text_message";
				$Refined->{text} = $msg;
			} elsif($type == 4) # URL
			{
				$Refined->{MessageType} = "URL";
				($Refined->{Description},$Refined->{URL}) = split /\xfe/,$msg;
			} elsif($type == 6) # Auth request
			{
				my($nick,$fname,$lname,$email,$xxx,$reason) = split /\xfe/,$msg;;
				$Refined->{nick} = $nick;
				$Refined->{first_name} = $fname;
				$Refined->{last_name} = $lname;
				$Refined->{email} = $email;
				$Refined->{reason} = $reason;
				$Refined->{MessageType} = "auth_request";
			} elsif($type == 0xC) # You have been added
			{
				$Refined->{MessageType} = "add_message";
			} elsif($type == 0x13) # Contacts
			{
				my ($contactcount,@contacts) = split /\xfe/,$msg;
				$Refined->{MessageType} = "contacts";
				$Refined->{Count} = $contactcount;
				$Refined->{Contacts} = \@contacts;
			}
		}

		return ($Refined);
	},
	'23:5' => sub {
		my ($Me, $event) = @_;
		$Me->{_NewUIN} = _endian_bytes_to_int($event->{Data_Load}, 56 , 4);
	},

	'23:1' => sub {
		my ($Me, $event) = @_;
		$Me->SetError("Request for registration rejected!");
	},
	#Srv_BOS_Rights
	'9:3' => sub {
		my ($Me, $event) = @_;
		my ($Refined);

		if ($Me->{_Auto_Login} > 1) {
			$Me->Send_Command("Cmd_Mes_Add_ICBM_Param");
			$Me->Send_Command("Cmd_LS_Set_User_Info");
			$Me->Send_Command("Cmd_CTL_UploadList", {ContactList=> $Me->{_Auto_Login_Contact_List}});
			$Me->Send_Command("Cmd_GSC_Set_Status", {Status => $Me->{_Status}});
			$Me->Send_Command("Cmd_GSC_Client_Ready");
			# now send all the Ad requests (hey, this is how the
			# client does it.. : /
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "request_offline"});
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "key", Key => "DataFilesIP"});
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "key", Key => "BannersIP"});
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "key", Key => "ChannelsIP"});

		}
		#$event->{Data_Load}
		return ($Refined);
	},
	# Srv_Contact_List
	'19:6' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $i);
		$i = 39;
		my $l = _bytes_to_int($event->{Data_Load}, $i, 1);
		open FILE,"> packet";
		foreach (@{$event->{Data_Load}})
		{
			print FILE chr($_);
		}
		close FILE;
		$i = 11;
		$Refined->{Groups} = _bytes_to_int($event->{Data_Load}, $i, 2);
		$i+=2;
		my $groups = $Refined->{Groups};
		while($groups)
		{
			my $strlen = _bytes_to_int($event->{Data_Load}, $i, 2);
			my $str = "";
			$i+=2;
			if($strlen) {
				$str = _bytes_to_str($event->{Data_Load}, $i, $strlen);
				$i += $strlen;
			}
			my $tag = _bytes_to_int($event->{Data_Load}, $i, 2);
			$i+=2;
			my $id = _bytes_to_int($event->{Data_Load}, $i, 2);
			$i+=2;
			my $type = _bytes_to_int($event->{Data_Load}, $i, 2);
			$i+=2;
			my $len = _bytes_to_int($event->{Data_Load}, $i, 2);
			$i+=2;
			my $data = "";
			my $tlv = 0xff;
			if ($len) {
				$tlv = _bytes_to_int($event->{Data_Load}, $i, 2);
				$i+=2;
				$data = _bytes_to_str($event->{Data_Load}, $i, $len-2);
				$i+= $len-2;
			}

			if($tag != 0) {
				if($tlv == 0xc8) {
					$Refined->{Groups}->{$tag}->{name} = $str;
				} elsif($tlv == 0x131) {
					my ($f,$s) = split //,$data;
					my $nicklen = (ord($f) * 8) + ord($s);
					$Refined->{Groups}->{$tag}->{uins}->{$str} = substr($data,2,$nicklen);
				}
			}
			# printf ">>>>[%x,%x] %s (%x,%d,%s)\n",$tag,$type,$str, $tlv, $len, substr($data,2) if ($tlv==0x131);
			# printf ">>>> %s (%x,%d,%s)\n",$str, $tlv, $len, $data if ($tlv==0x131);
			# printf ">>>>[%x,%x] %s (%x,%d)\n",$tag,$type,$str, $tlv, $len if ($tlv!=0x131);
			$groups--;
		}
		return ($Refined);
	},
	#Srv_Srv_Message
	'21:3' => sub {
		my ($Me, $event) = @_;
		my ($Refined, $i);

################
##### NOTE #####
################
# This Srv response seems to be the one that AOL decided to hack ALL ICQ
# functions that they couldn't fit under the normal AIM protocol. This means
# that this family seems to ave a lot of sub sub sub families, and hence is
# a bastard to decode, and then when u think u've got it, one call out of
# 900000 screws up in the decoding so if anyone has some good insights into
# this family please let me know!!!!

		print "Incoming..\n" if $Me->{_Debug};
		print "[".$event->{Channel_ID}."][".$event->{Sequence_ID}."][".$event->{Data_Size}."][".$event->{Family_ID}."][".$event->{Sub_ID}."]\n" if $Me->{_Debug};
		_print_packet($event->{Data_Load}, ()) if $Me->{_Debug};

		$Refined->{Flags} = _bytes_to_int($event->{Data_Load}, 4, 2);
		$Refined->{Ref} = _bytes_to_int($event->{Data_Load}, 6, 4);

		if (exists $Me->{_Sent_Requests}{$Refined->{Ref}}) {
			$Refined->{Responce_Type} = $Me->{_Sent_Requests}{$Refined->{Ref}};
			undef $Me->{_Sent_Requests}{$Refined->{Ref}};
		}

		#first ten is SNAC header, then a 00 01 (normally..) then the message's size in
		#Normal then endian format (don't have any idea why, but it is..) but skip all that..
		$i = 16;
		$Refined->{Our_UIN} = _endian_bytes_to_int($event->{Data_Load}, $i, 4);$i += 4;

		#the first of the sub sub types..
		$Refined->{MessageType} = _endian_bytes_to_int($event->{Data_Load}, $i, 2);$i += 2;
		# print "\n>> ",$Refined->{MessageType}," << \n";
		if ($Refined->{MessageType} == 65){
			# normally offline messages..
			if (_endian_bytes_to_int($event->{Data_Load}, $i, 2) == 2) {
				#90% sure it's an offline message..
				$i += 2;
				$Refined->{Sender} = _endian_bytes_to_int($event->{Data_Load}, $i, 4);$i += 4;

				#note, the time given is in GMT, not local, so make it local..(DIE AOL!!!)
				$Refined->{Sent_Time} = localtime(timegm(0,
					_endian_bytes_to_int($event->{Data_Load}, $i+5, 1),
					_endian_bytes_to_int($event->{Data_Load}, $i+4, 1),
					_endian_bytes_to_int($event->{Data_Load}, $i+3, 1),
					_endian_bytes_to_int($event->{Data_Load}, $i+2, 1)-1,
					_endian_bytes_to_int($event->{Data_Load}, $i,2)));
				$i += 6;

				$Refined->{Message_Encoding} = _endian_bytes_to_int($event->{Data_Load}, $i, 1);
				$i++;
				$Refined->{Message_Flags} = _endian_bytes_to_int($event->{Data_Load}, $i, 1);
				$i+=1;
				my $DataLength=0;
				# print "\n $DataLength \n//==> $Refined->{Message_Encoding} $Refined->{Message_Flags}\n\n";
				if ($Refined->{Message_Encoding} == 1) {
					#normal text message..
					$Refined->{MessageType} = "offline_text_message";
					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					$Refined->{text} = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					$Refined->{text} =~ s/\r\n/\n/g;
				} elsif ($Refined->{Message_Encoding} == 4) {
					$Refined->{MessageType} = "URL";
					# $DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					# my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					# ($Refined->{Description},$Refined->{URL}) = split /\xfe/,$data;
					($Refined->{Description},$Refined->{URL}) = GetURLMessage($event->{Data_Load}, $i);
				} elsif ($Refined->{Message_Encoding} == 5) {
					my $DataLength = _bytes_to_int($event->{Data_Load}, $i, 2);
					$i+=2;
					$i+=4;
					my $type = ord(_bytes_to_str($event->{Data_Load}, $i, 1));
					$i++;
					# print "++> $type";
					if($type == 48) # Auth request!  
					{
						$i++;
						my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
						my($nick,$fname,$lname,$email,$xxx,$reason);
						$Refined->{nick} = $nick;
						$Refined->{first_name} = $fname;
						$Refined->{last_name} = $lname;
						$Refined->{email} = $email;
						$Refined->{reason} = $data;
						$Refined->{MessageType} = "auth_request";
					}

				} elsif ($Refined->{Message_Encoding} == 26) {
					$i += 2;
					my $type = _bytes_to_int($event->{Data_Load}, $i, 2);
					if($type == 0x39) {
						$i += 21;
						my $length = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
						$i += 4;
						my $s = _bytes_to_str($event->{Data_Load},$i,$length);
						$i += $length;
						$i += 19;
						$length = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
						$i += 4;
						my $reason = _bytes_to_str($event->{Data_Load},$i,$length);
						$Refined->{MessageType} = "contacts_request";
						$Refined->{Reason} = $reason;

					} elsif($type == 0x20) {
						$i += 21;
						my $length = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
						$i += 4;
						my $s = _bytes_to_str($event->{Data_Load},$i,$length);
						$i += $length;
						$i += 7;
						$length = _endian_bytes_to_int($event->{Data_Load}, $i, 4);
						$i += 4;
						$s = _bytes_to_str($event->{Data_Load},$i,$length);
						$Refined = _Decode_Tagged_Text($s);
					} 

				} elsif ($Refined->{Message_Encoding} == 14) {

					$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
					my $data = _bytes_to_str($event->{Data_Load}, $i+2, $DataLength);
					$Refined->{MessageType} = 'email_message';
					my ($name,$junk,$junk2,$email,$junk3,$text) = split /\xfe/,$data;
					$Refined->{Name} = $name;
					$Refined->{Email} = $email;
					$Refined->{Text} = $text;
				} elsif ($Refined->{Message_Encoding} == 19) {
						$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
						$i+=2;
						my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
						my ($contactcount,@contacts) = split /\xfe/,$data;
						$Refined->{MessageType} = "contacts";
						$Refined->{Count} = $contactcount;
						$Refined->{Contacts} = \@contacts;
				} elsif ($Refined->{Message_Encoding} == 6) {
						$DataLength = _bytes_to_int ($event->{Data_Load}, $i, 2);
						$i+=2;
						my $data = _bytes_to_str($event->{Data_Load}, $i, $DataLength-4);
						my($nick,$fname,$lname,$email,$xxx,$reason) = split /\xfe/,$data;;
						$Refined->{nick} = $nick;
						$Refined->{first_name} = $fname;
						$Refined->{last_name} = $lname;
						$Refined->{email} = $email;
						$Refined->{reason} = $reason;
						$Refined->{MessageType} = "auth_request";

				}

			} else {
				print "Argh, something Screwed up!!!";
				return;
			}

		} elsif ($Refined->{MessageType} == 66) {
			# End of offline messages
			$Me->Send_Command("Cmd_Srv_Message", {MessageType => "ack_offline"});
			$Refined->{MessageType} = "ack_offline";
		} elsif ($Refined->{MessageType} == 2010) {
			#Server messages stored in "html" style tags..
			$i += 2;


			$Refined->{SubMessageType} = _bytes_to_int($event->{Data_Load}, $i, 3); $i+=3;
			# print ">> ", $Refined->{SubMessageType}, "\n";

			if($Refined->{SubMessageType} == 9830410) {
				if (_bytes_to_int($event->{Data_Load}, $i, 2) == 41480) {
					#short gap.. (this is a VERY bad way of doing this.. should fix..)
					$i += 3;
				} else {
					#don't know what these 11(?) bytes do..
					$i += 11;
				}


				$Refined->{TaggedDataString} = _bytes_to_str($event->{Data_Load}, $i+3, _bytes_to_int($event->{Data_Load}, $i, 2));
				$Refined = _Decode_Tagged_Text($Refined->{TaggedDataString}, $Refined);

			} elsif($Refined->{SubMessageType} == 262410) {
				my($BytesToCount);
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Nickname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Firstname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Lastname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Email}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{MessageType}	= 'user_short_info';

			} elsif($Refined->{SubMessageType} == 262420) {
				$Refined->{MessageType} = "user_info_not_found";
			} elsif($Refined->{SubMessageType} == 10618890) {
				#Ads stuff
				$Refined->{MessageType} = "Tagged_Srv_Responce";
				if (_bytes_to_int($event->{Data_Load}, $i, 2) == 41480) {
					#short gap.. (this is a VERY bad way of doing this.. should fix..)
					$i += 3;
				} else {
					#don't know what these 11(?) bytes do..
					$i += 11;
				}

				$Refined->{TaggedDataString} = _bytes_to_str($event->{Data_Load}, $i+2, _bytes_to_int($event->{Data_Load}, $i, 2));
				$Refined = _Decode_Tagged_Text($Refined->{TaggedDataString}, $Refined);

			} elsif($Refined->{SubMessageType} == 10748170) {
			#Info Request return)
				my($BytesToCount);
				$Refined->{MessageType} ="wp_result_info";
				#Unknown word
				$i += 2;
				$Refined->{UIN}		= _endian_bytes_to_int($event->{Data_Load}, $i, 4); $i += 4;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Nickname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Firstname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Lastname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Email}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$Refined->{Auth_Required} = _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;
				$Refined->{Status}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 1;
				#always ends with a 00

			} elsif($Refined->{SubMessageType} == 10748210 || $Refined->{SubMessageType} == 11403570) {
				$Refined->{MessageType} = "wp_empty";
				#Empty White Page Result

			} elsif(($Refined->{SubMessageType} & 0xffff00) == 0x640000){ #11403530) {
				$Refined->{MessageType} ="set_main_info_ack";
			} elsif(($Refined->{SubMessageType} & 0xffff00) == 0xA00000){ #11403530) {
				$Refined->{MessageType} ="set_permissions_ack";
			} elsif(($Refined->{SubMessageType} & 0xffff00) == 0xae0100){ #11403530) {
				my($BytesToCount);
				$Refined->{MessageType} ="wp_final_result_info";
				#Unknown word
				$i += 2;
				$Refined->{UIN}		= _endian_bytes_to_int($event->{Data_Load}, $i, 4); $i += 4;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Nickname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Firstname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Lastname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Email}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$Refined->{Auth_Required} = _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;
				$Refined->{Status}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 1;
				#Some weird 3 bytes are thrown in - perhaps
				#a counter for total unreturned results?
				#always ends with 00

			} elsif($Refined->{SubMessageType} == 13107210) {
				my ($BytesToCount);
				$Refined->{MessageType} = "user_info_main";

				#This isn't really correct, since it's endian data and not normal, but
				# this will only be shown if any name etc is longer then 255 chars..
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Nickname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Firstname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Lastname}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Email}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{City}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{State}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Telephone}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Fax_Num}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Address}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Mobile_Phone} = _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Zip}		= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$Refined->{Country}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 2;
				$Refined->{GMT_Code}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 2;

			} elsif($Refined->{SubMessageType} == 15400970) {
				my($BytesToCount, $Extra_Email_Count);
				$Refined->{MessageType} = "user_info_extra_emails";

				$Extra_Email_Count = $Refined->{Extra_Email_Count} = _bytes_to_int($event->{Data_Load}, $i, 1); $i += 2;

				#Grab all the extra E-mails, and place them into an array..
				while ($Extra_Email_Count > 0) {
					$BytesToCount = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					push(@{$Refined->{Extra_Emails}}, _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1)); $i += $BytesToCount+1;
					$Extra_Email_Count--;
				}

			} elsif($Refined->{SubMessageType} == 14417930) {
				my ($BytesToCount);
				$Refined->{MessageType} = "user_info_homepage";

				#one of the 0 bytes may be the homepage category, but who cares about that
				$Refined->{Age}		= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 2;
				$Refined->{Sex}		= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 1;
				$BytesToCount		= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Homepage}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$Refined->{Birth_Year}	= _endian_bytes_to_int($event->{Data_Load}, $i, 2); $i +=2;
				$Refined->{Birth_Month}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;
				$Refined->{Birth_Day}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;
				$Refined->{Language1}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;
				$Refined->{Language2}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;
				$Refined->{Language3}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i +=1;

			} elsif($Refined->{SubMessageType} == 917770) {
				$Refined->{MessageType} = "user_info_unknown";
			} elsif($Refined->{SubMessageType} == 16384020) {
				$Refined->{MessageType} = "user_info_not_found";
			} elsif($Refined->{SubMessageType} == 13762570) {
				my($BytesToCount);
				$Refined->{MessageType} = "user_info_work";

				#work DC000A
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_City}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_State}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Phone}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Fax}		= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;

				# odd 6 bytes, 2 sets of 01 00 00, almost
				# like 2 sets of dwords that are empty
				# $i += 4;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Address}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Zip}		= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				# $i+=2;
				$Refined->{Company_Country}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i +=2;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Name}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Department}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_Position}	= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
				$Refined->{Company_Occupation}	= _bytes_to_int($event->{Data_Load}, $i, 1); $i += 2;
				$BytesToCount			= _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{Company_URL}		= _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;

			} elsif($Refined->{SubMessageType} == 15073290) {
			#about)
				my ($BytesToCount);
				$Refined->{MessageType} = "user_info_about";
				$BytesToCount = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
				$Refined->{about} = _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1); $i += $BytesToCount;
			} elsif($Refined->{SubMessageType} == 15728650 ) {
			#Personal Interests)
				my ($BytesToCount, $Int_Count);
				$Refined->{MessageType} = "user_info_personal_interests";

				$Int_Count = $Refined->{Interests_Count} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=1;

				while ($Int_Count >0) {
					$Int_Count--;

					push(@{$Refined->{Interests_Type}}, _bytes_to_int($event->{Data_Load}, $i, 2)); $i += 2;
					$BytesToCount = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					push(@{$Refined->{Interests_Desc}}, _bytes_to_str($event->{Data_Load}, $i, $BytesToCount-1)); $i += $BytesToCount;
				}

			} elsif($Refined->{SubMessageType} == 16384010) {
			#Past Interests Info)
				$Refined->{MessageType} = "user_info_past_background";
				$Refined->{_background_count} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=1;
				if($Refined->{_background_count} > 0) {
					$Refined->{_background_category1} = _bytes_to_int($event->{Data_Load}, $i, 2); $i += 2;
					$Refined->{BytesToCount} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					$Refined->{_background_description1} = _bytes_to_str($event->{Data_Load}, $i, $Refined->{BytesToCount}-1); $i += $Refined->{BytesToCount};
				}
				if($Refined->{_background_count} > 1) {
					$Refined->{_background_category2} = _bytes_to_int($event->{Data_Load}, $i, 2); $i += 2;
					$Refined->{BytesToCount} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					$Refined->{_background_description2} = _bytes_to_str($event->{Data_Load}, $i, $Refined->{BytesToCount}-1); $i += $Refined->{BytesToCount};
				}
				if($Refined->{_background_count} > 2) {
					$Refined->{_background_category3} = _bytes_to_int($event->{Data_Load}, $i, 2); $i += 2;
					$Refined->{BytesToCount} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					$Refined->{_background_description3} = _bytes_to_str($event->{Data_Load}, $i, $Refined->{BytesToCount}-1); $i += $Refined->{BytesToCount};
				}
				$Refined->{_organization_count} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=1;
				if($Refined->{_organization_count} > 0) {
					$Refined->{_organization_category1} = _bytes_to_int($event->{Data_Load}, $i, 2); $i += 2;
					$Refined->{BytesToCount} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					$Refined->{_organization_description1} = _bytes_to_str($event->{Data_Load}, $i, $Refined->{BytesToCount}-1); $i += $Refined->{BytesToCount};
				}
				if($Refined->{_organization_count} > 1) {
					$Refined->{_organization_category2} = _bytes_to_int($event->{Data_Load}, $i, 2); $i += 2;
					$Refined->{BytesToCount} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					$Refined->{_organization_description2} = _bytes_to_str($event->{Data_Load}, $i, $Refined->{BytesToCount}-1); $i += $Refined->{BytesToCount};
				}
				if($Refined->{_organization_count} > 2) {
					$Refined->{_organization_category3} = _bytes_to_int($event->{Data_Load}, $i, 2); $i += 2;
					$Refined->{BytesToCount} = _bytes_to_int($event->{Data_Load}, $i, 1); $i+=2;
					$Refined->{_organization_description3} = _bytes_to_str($event->{Data_Load}, $i, $Refined->{BytesToCount}-1); $i += $Refined->{BytesToCount};
				}
			} elsif($Refined->{SubMessageType} == 6685450) {
				$Refined->{MessageType} = "random_uin";
				$Refined->{UIN} = _endian_bytes_to_int($event->{Data_Load}, $i, 4); $i+=4;
				$Refined->{Sender} = "010"; # hmmmm
			} elsif($Refined->{SubMessageType} == 0x70030a) {
				$Refined->{MessageType} = "group_set";
				$Refined->{Sender} = "010"; # hmmmm
			} elsif($Refined->{SubMessageType} == 0xaa000a) {
				$Refined->{MessageType} = "password_set";
				$Refined->{Sender} = "010"; # hmmmm
			} elsif($Refined->{SubMessageType} == 0x00010046) {
				$Refined->{MessageType} = "sms_error";
				my $length = 0;
				# NTS with error message following
				while($event->{Data_Load}[$i+$length] != 0) {
					$length++;
				}
				$Refined->{Text} = _bytes_to_str($event->{Data_Load}, $i, $length);
			} else {
				print ">>Unknown SubMessageType: ", $Refined->{SubMessageType}, "\n";
			}

		}

		return ($Refined);
	}
);

%_Cmd_Codes = (
	Cmd_GSC_Client_Ready =>		"1:2",
	Cmd_GSC_Reqest_Rate_Info =>	"1:6",
	Cmd_GSC_LoggedIn_User_Info =>	"1:14",
	Cmd_GSC_ICQInform =>		"1:23",
	Cmd_GSC_Set_Status =>		"1:30",
	Cmd_LS_LoggedIn_User_Rights =>	"2:2",
	Cmd_LS_Set_User_Info =>		"2:4",
	Cmd_BLM_Rights_Info =>		"3:2",
	Cmd_CTL_UploadList =>		"3:4",
	Cmd_Mes_Add_ICBM_Param =>	"4:2",
	Cmd_Mes_Param_Info =>		"4:4",
	Cmd_Type2_Ack	=>			"4:11",
	Cmd_BOS_Get_Rights =>		"9:2",
	Cmd_BOS_Add_VisibleList =>	"9:5",
	Cmd_BOS_Remove_VisibleList =>	"9:6",
	Cmd_BOS_Add_InVisibleList =>	"9:7",
	Cmd_BOS_Remove_InVisibleList =>	"9:8",
	Cmd_BOS_Add_GenericList =>	"9:10",
	Cmd_BOS_Remove_GenericList =>	"9:11",
	Cmd_Srv_Message =>		"21:2",
	Cmd_Send_Message =>		"4:6",
	Cmd_Add_ContactList =>		"19:20",
	Cmd_Add_List =>			"19:8",
	Cmd_Update_Group =>			"19:9",
	Cmd_RemoveVisibleList =>	"19:10",
	Cmd_Unk =>			"19:17",
	Cmd_Init_Contacts =>		"19:2",
	Cmd_Get_List =>			"19:5",
	Cmd_Authorize =>		"19:26",
	Cmd_Register =>			"23:4"
);



%_Srv_Codes = (
	Srv_GSC_Error =>		"1:1",
	Srv_GSC_Ready =>		"1:3",
	Srv_GSC_Redirect =>		"1:5",
	Srv_GSC_Rate_Info =>		"1:7",
	Srv_GSC_Rate_Change =>		"1:10",
	Srv_GSC_User_Info =>		"1:15",
	Srv_GSC_MOTD =>			"1:19",
	Srv_GSC_ICQClientConfirm =>	"1:24",
	Srv_LS_Rights_Response =>	"2:3",
	Srv_BLM_Rights_Response =>	"3:3",
	Srv_BLM_Contact_Online =>	"3:11",
	Srv_BLM_Contact_Offline =>	"3:12",
	Srv_Mes_Rights_Response =>	"4:5",
	Srv_Mes_Received =>		"4:7",
	Srv_BOS_Rights =>		"9:3",
	Srv_Password_Missmatch =>	"9:9",
	Srv_Srv_Message =>		"21:3",
	Srv_Contact_List =>		"19:6",
	Srv_Registered =>		"23:7",
	DC_Message =>			"DC:2",
	File_Offer =>			"File:2"
);


%_New_Connection_Nefotiation_Codes = (
	1 => sub {
		my ($Me, $event) = @_;
		my($Responce);
		if($Me->{_Register}) {
			$Responce->{Channel_ID} = 1;
			@{$Responce->{Data_Load}} = _int_to_bytes(4, 1);
			push(@{$Me->{_Outgoing_Queue}}, $Responce);
			$Me->Send_Command("Cmd_Register",{ password => $Me->{_Password}});
			return;
		}
		# print "Sending Connection reply..\n";
		print ".";

		if ($Me->{_Connection_Cookie}) {
			# print "Sending Cookie\n";
			print ".";
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
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'UIN', $Me->{_UIN}));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'Password', &_Password_Encrypt($Me->{_Password})));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientProfile', "ICQ Inc. - Product of ICQ (TM).2000b.4.63.1.3279.85"));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientType', 266));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientVersionMajor', 5));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientVersionMinor', 63));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientICQNumber', 1));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientBuildMajor', 3279));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'ClientBuildMinor', 85));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'Language', "en"));
		push(@{$Responce->{Data_Load}}, _Write_TLV(1, 'CountryCode', "us"));
		push(@{$Me->{_Outgoing_Queue}}, $Responce);
	}
);

sub _Disconnection_Nefotiation
{
	my ($Me, $event) = @_;
	my ($Details, $i);
	print "xIncoming..\n" if $Me->{_Debug};
	_print_packet($event->{Data_Load}, ()) if $Me->{_Debug};

	($Details, $i) = &_Read_TLV($event->{Data_Load}, 4);
	if($Details->{Error_Code}) {

		$Me->SetErrorCode($Details->{Error_Code});
		$Me->Disconnect;
		return -1;
	}

	if($Details->{Dual_User_Online}) {
		$Me->SetError("Another user logged in with your UIN, disconnected..");
		$Me->Disconnect;
		return -1;
	}
	# if ($Details->{UIN} != $Me->{_UIN})
	# {
		# $Me->SetError("Server got our UIN wrong!![".$Details->{UIN}."]");
		# return;
	# }

	$Me->{_Connection_Cookie} = $Details->{Connection_Cookie} if ($Details->{Connection_Cookie});
	if ($Details->{Server_And_Port}) {
		#we've been told to disconnect, and reconnect...
		# print "Disconnecting as instructed..\n";
		$Me->Disconnect();

		#change the server we are going to access...
		($Me->{_Server}, $Me->{_ServerPort}) = split (/:/, $Details->{Server_And_Port});
		print "Changing to server [".$Me->{_Server}."][".$Me->{_ServerPort}."]\n" if ($Me->{_Debug});

		$Me->Connect();
	} elsif ($Details->{Password_Error}) {
		#run the PasswordError hook 9,9
		# if (exists $Me->{_Hooks}{$_->{9}{9}} ) {
			# &{$Me->{_Hooks}{9}{9}}($Me, $_)
		# }

		if (exists $Me->{_Hooks}{"9:9"} ) {
			&{$Me->{_Hooks}{"9:9"}}($Me, $_)
		}
	} elsif ($Details->{Dual_User_Online}) {
		#run the DualUserError hook 9,10
		if (exists $Me->{_Hooks}{$_->{9}{10}} ) {
			&{$Me->{_Hooks}{9}{10}}($Me, $_)
		}
	} else
	{
	}

	if($Me->{_LoggedIn}) {
		$Me->SetError("Disconnected by server");
	}
	return 0;
}


sub File_Handle_Incoming
{
	my ($Me,$connection) = @_;
	my $socket = $connection->{Socket};
	my $select = $connection->{Select};
	my @Reply = ();
	while (IO::Select->select($select, undef, undef, .00001)) {
		my $RawPacket;
		$socket->recv($RawPacket, 10000);
		if (length($RawPacket)==0) {
			$connection->{Disconnected} = 1;
			last;
		}
		my @Packet = split(//, $RawPacket);
		foreach (@Packet)
		{
			$_ = ord;
		}
		@{$connection->{Packet}} = (@{$connection->{Packet}}, @Packet);
		@Packet = @{$connection->{Packet}};
		my $len = @Packet;

		if($len>2) {
			my $datalen = _endian_bytes_to_int(\@Packet, 0, 2);
			$len = @Packet;
			while($datalen+2 <= $len) # We have Full packet
			{
				if($connection->{State}==1) {
					my $id = _bytes_to_int(\@Packet, 2, 1);
					if($id != 0xff) {
						SetError("Direct Connection data misalligned!");
						$connection->{Disconnected} = 1;
						last;
					}
					my $ruin = _endian_bytes_to_int(\@Packet,17,4);
					$connection->{UIN} = $ruin;
					my $sid = _endian_bytes_to_int(\@Packet,34,4);
					my $port = $Me->{_FilePort};
					my @tmp = _int_to_endian_bytes(4,$Me->{_UIN});
					my $ip = inet_aton($Me->{_DCIP});
					push(@Reply, _int_to_endian_bytes(2,4)); #length
					push(@Reply, _int_to_endian_bytes(4,1)); # 1
					# INIT2
					push(@Reply, _int_to_endian_bytes(2,0x30)); # length
					push(@Reply, _int_to_endian_bytes(1,0xff)); # ID
					push(@Reply, _int_to_endian_bytes(2,0x07)); # Version
					push(@Reply, _int_to_endian_bytes(2,0x2b)); # ???
					push(@Reply, _int_to_endian_bytes(4,$ruin)); # Remote UIN
					push(@Reply, _int_to_endian_bytes(2,0x0)); # ??
					push(@Reply, _int_to_endian_bytes(4,$port)); # Listen port
					push(@Reply, _int_to_endian_bytes(4,$Me->{_UIN})); # My UIN
					push(@Reply, _str_to_bytes($ip)); # External IP
					# TODO Make Local/External IPs different
					push(@Reply, _str_to_bytes($ip)); # Local IP
					push(@Reply, _int_to_endian_bytes(1,0x04)); # TCP flag
					push(@Reply, _int_to_endian_bytes(4,$port)); # listen port
					push(@Reply, _int_to_endian_bytes(4,$sid)); # sid
					push(@Reply, _int_to_endian_bytes(4,0x00000050)); # ?
					push(@Reply, _int_to_endian_bytes(4,0x00000003)); # ?
					push(@Reply, _int_to_endian_bytes(4,0x00000000)); # ?
					$connection->{State}++;

				} elsif($connection->{State} == 2) {
				# INIT_ACK
					my $data = _endian_bytes_to_int(\@Packet, 2, 4);
					if(($datalen != 4) || ($data != 1)) { 
						SetError("DC: INIT_ACK failed");
						$connection->{Disconnected} = 1;
						last;
					}
					$connection->{State}++;

				} elsif($connection->{State} == 3) {
				# INIT_ACK
					my $id = _endian_bytes_to_int(\@Packet, 2, 1);
					my $ID = "File:$id";
					# print "\n>>>>> $ID\n";
					print "can't run sub!![$ID]\n" if ( !(exists $_FileDC_Decoder{$ID}) );
					my ($Refined);
					$Refined = &{$_FileDC_Decoder{$ID}}($Me,
						{ Data_Load => \@Packet ,
						Connection => $connection} )
						if ( exists $_FileDC_Decoder{$ID} );
						&{$Me->{_Hooks}{$ID}}($Me, $Refined) if exists $Me->{_Hooks}{$ID};
				}
				$datalen += 2;
				splice @{$connection->{Packet}},0,$datalen;
				splice @Packet,0,$datalen;
				my $l = @Packet;
				if(@Packet > 2) {
					$datalen = _endian_bytes_to_int(\@Packet, 0, 2);
				} else {
					$datalen = 0xffffffff;
				}
			}
		}
	}

	if(@Reply) {
		push(@{$connection->{ToSend}},@Reply);
	}
}

sub File_Handle_Outgoing
{
	my ($Me,$connection) = @_;

	my $select = $connection->{Select};
	my $socket = $connection->{Socket};
	# if(IO::Select->select(undef, $select, undef, .00001)) {
		my $RawData = '';
		foreach (@{$connection->{ToSend}})
		{
			$RawData .= chr $_;
		}
		my $result = 0;
		eval { $result = $socket->send($RawData); };
		if(($result > 0) || $@) {
			splice @{$connection->{ToSend}},0,$result;
		} else {
			$connection->{Diconnected} = 1;
		}
	# }
}


sub DC_Handle_Incoming
{
	my ($Me,$connection) = @_;
	my $socket = $connection->{Socket};
	my $select = $connection->{Select};
	my @Reply = ();
	while (IO::Select->select($select, undef, undef, .00001)) {
		my $RawPacket;
		$socket->recv($RawPacket, 10000);
		if (length($RawPacket)==0) { $connection->{Disconnected} = 1;
			last;
		}
		my @Packet = split(//, $RawPacket);
		foreach (@Packet)
		{
			$_ = ord;
		}
		@{$connection->{Packet}} = (@{$connection->{Packet}}, @Packet);
		@Packet = @{$connection->{Packet}};
		my $len = @Packet;

		if($len>2) {
			my $datalen = _endian_bytes_to_int(\@Packet, 0, 2);
			$len = @Packet;
			while($datalen+2 <= $len) # We have Full packet
			{
				if($connection->{State}==1) {
					my $id = _bytes_to_int(\@Packet, 2, 1);
					if($id != 0xff) {
						SetError("Direct Connection data misalligned!");
						$connection->{Disconnected} = 1;
						last;
					}
					my $ruin = _endian_bytes_to_int(\@Packet,17,4);
					$connection->{UIN} = $ruin;
					my $sid = _endian_bytes_to_int(\@Packet,34,4);
					# my $sid = chr ($Packet[34]) . chr ($Packet[35]) . chr ($Packet[36]) . chr ($Packet[37]);
					my $port = $Me->{_DCPort};
					my @tmp = _int_to_endian_bytes(4,$Me->{_UIN});
					my $ip = inet_aton($Me->{_DCIP});
					push(@Reply, _int_to_endian_bytes(2,4)); #length
					push(@Reply, _int_to_endian_bytes(4,1)); # 1
					# INIT2
					push(@Reply, _int_to_endian_bytes(2,0x30)); # length
					push(@Reply, _int_to_endian_bytes(1,0xff)); # ID
					push(@Reply, _int_to_endian_bytes(2,0x07)); # Version
					push(@Reply, _int_to_endian_bytes(2,0x2b)); # ???
					push(@Reply, _int_to_endian_bytes(4,$ruin)); # Remote UIN
					push(@Reply, _int_to_endian_bytes(2,0x0)); # ??
					push(@Reply, _int_to_endian_bytes(4,$port)); # Listen port
					push(@Reply, _int_to_endian_bytes(4,$Me->{_UIN})); # My UIN
					push(@Reply, _str_to_bytes($ip)); # External IP
					# TODO Make Local/External IPs different
					push(@Reply, _str_to_bytes($ip)); # Local IP
					push(@Reply, _int_to_endian_bytes(1,0x04)); # TCP flag
					push(@Reply, _int_to_endian_bytes(4,$port)); # listen port
					push(@Reply, _int_to_endian_bytes(4,$sid)); # sid
					push(@Reply, _int_to_endian_bytes(4,0x00000050)); # ?
					push(@Reply, _int_to_endian_bytes(4,0x00000003)); # ?
					push(@Reply, _int_to_endian_bytes(4,0x00000000)); # ?
					$connection->{State}++;

				} elsif($connection->{State} == 2) {
				# INIT_ACK
					my $data = _endian_bytes_to_int(\@Packet, 2, 4);
					if(($datalen != 4) || ($data != 1)) {

						SetError("DC: INIT_ACK failed");
						$connection->{Disconnected} = 1;
						last;
					}
					$connection->{State}++;

				} elsif($connection->{State} == 3) {
				# INIT_ACK
					my $id = _endian_bytes_to_int(\@Packet, 2, 1);
					my $data = _endian_bytes_to_int(\@Packet, 7, 4);
					if(($datalen != 0x21) || ($id != 3) || ($data != 0x1)) {
						# open FILE,"> packet";
						# foreach (@Packet)
						# {
							# print FILE chr($_);
						# }
						# close FILE;
						$connection->{Disconnected} = 1;
						last;
					}
					push(@Reply, _int_to_endian_bytes(2,0x21)); #length
					push(@Reply, _int_to_endian_bytes(1,3)); # 3
					push(@Reply, _int_to_endian_bytes(4,0x0a)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x01)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x01)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x00)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x00)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x00040001)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x00)); # ??
					push(@Reply, _int_to_endian_bytes(4,0x00)); # ??
					$connection->{State}++;

				} else {
					my $id = _endian_bytes_to_int(\@Packet, 2, 1);
					my $ID = "DC:$id";
					if (exists $Me->{_Hooks}{$ID} ) {

							#decode the Sub_ID etc..
							if(!(@Packet = Decrypt(\@Packet))) {
								return -1;
							}

							my $cmd = _endian_bytes_to_int(\@Packet, 7, 2);
							# my $type = _endian_bytes_to_int(\@Packet, 25, 1);
							my $dcID = "DC:$cmd";
							print "can't run sub!![$dcID]\n" if ( !(exists $_DC_Decoder{$dcID}) );
							my ($Refined);
							$Refined = &{$_DC_Decoder{$dcID}}($Me, { Data_Load => \@Packet , Connection => $connection} )
								if ( exists $_DC_Decoder{$dcID} );
							&{$Me->{_Hooks}{$ID}}($Me, $Refined);
					}
				}
				$datalen += 2;
				splice @{$connection->{Packet}},0,$datalen;
				splice @Packet,0,$datalen;
				my $l = @Packet;
				if(@Packet > 2) {
					$datalen = _endian_bytes_to_int(\@Packet, 0, 2);
				} else {
					$datalen = 0xffffffff;
				}
			}
		}
	}

	if(@Reply) {
		push(@{$connection->{ToSend}},@Reply);
	}
}

sub DC_Handle_Outgoing
{
	my ($Me,$connection) = @_;

	my $select = $connection->{Select};
	my $socket = $connection->{Socket};
	# if(IO::Select->select(undef, $select, undef, .00001)) {
		my $RawData = '';
		foreach (@{$connection->{ToSend}})
		{
			$RawData .= chr $_;
		}
		my $result = 0;
		eval { $result = $socket->send($RawData); };
		if(($result > 0) || $@) {
			splice @{$connection->{ToSend}},0,$result;
		} else {
			$connection->{Diconnected} = 1;
		}
	# }
}

sub HandleDC
{
	my ($Me) = @_;
	# my $connections = @{$Me->{_DCs}};
	my $sock;
	# Terminal problems with 5.00503 IO::Socket::INET->accept
	# its just a fragment from Socket.pm of 5.6.0
	my $sel = new IO::Select $Me->{_DCSocket};
	if($sel->can_read(0.005)) {
		if($sock = $Me->{_DCSocket}->accept()) {
			push @{$Me->{_DCs}},{
				Socket => $sock,
				Select => IO::Select->new($sock),
				State => 1,	# 1 - Waiting for INIT
						# 2 - Waiting for INIT_ACK
						# 3 - Waiting for INIT2
						# 4 - Waiting for INIT2_ACK
				Packet => []};
				# print "\nDirect connection from ", $sock->peerhost(), ':' , $sock->peerport();
			# print "\n";
		} else {
			$@ = undef;
		}
	}

	my $connection = undef;
	my @tmp = ();
	foreach $connection (@{$Me->{_DCs}})
	{
		if(!$connection->{Disconnected}) {
			# TODO Make DC.pm
			$Me->DC_Handle_Incoming($connection);
			my $size = @{$connection->{ToSend}};
			$Me->DC_Handle_Outgoing($connection);
			push @tmp,$connection;
		}
	}
	@{$Me->{_DCs}} = @tmp;
	# cleanup
}

sub HandleFileDC
{
	my ($Me) = @_;
	my $sock;
	# Terminal problems with 5.00503 IO::Socket::INET->accept
	# its just a fragment from Socket.pm of 5.6.0
	my $sel = new IO::Select $Me->{_FileSocket};
	if($sel->can_read(0.005)) {
		if($sock = $Me->{_FileSocket}->accept()) {
			push @{$Me->{_FileDCs}},{
				Socket => $sock,
				Select => IO::Select->new($sock),
				State => 1,	# 1 - Waiting for INIT
						# 2 - Waiting for INIT_ACK
						# 3 - Waiting for INIT2
						# 4 - Waiting for INIT2_ACK
				Packet => []};
		} else {
			$@ = undef;
		}
	}

	my $connection = undef;
	my @tmp = ();
	foreach $connection (@{$Me->{_FileDCs}})
	{
		if(!$connection->{Disconnected}) {
			# TODO Make DC.pm
			$Me->File_Handle_Incoming($connection);
			my $size = @{$connection->{ToSend}};
			$Me->File_Handle_Outgoing($connection);
			push @tmp,$connection;
		}
	}
	@{$Me->{_FileDCs}} = @tmp;
}


sub Check_Incoming
{
	my ($Me) = @_;
	my($RawPacket, @Packet,$http_status);

	while (IO::Select->select($Me->{_Select}, undef, undef, .00001)) {
		$Me->{_Socket}->recv($RawPacket, 10000);

		if (!$RawPacket) {
			# print "==> ",POSIX::errno(),"\n";
			# print "recv error: $!\n";
			$Me->SetError("recv error");
			$Me->Disconnect;
			return;
		}
		# @Packet = split(//, $RawPacket);
		# print ">>",length($RawPacket), "\n";

		# open F,">> flow";
		# print F $RawPacket;
		# close F;

		if( $Me->{_Proxy_Type} eq 'https' && $RawPacket =~ /^HTTP\/1\.[01]\s+(\d+)/) {
			$http_status = $1;
			if ( $http_status != 200 ) {
				$Me->SetError( "HTTP proxy error: status $http_status");
				$Me->Disconnect;
				return;
			} else {
				$RawPacket =~ s/^HTTP.*(\r?\n)\1//s;
			}
		}
		@Packet = split(//, $RawPacket);

		foreach (@Packet) {
			$_ = ord;
		}

		my $PLength = @Packet;
		#decode the packet into FLAPs
		for(my $i =0; $i < $PLength; $i++) {

			if ($Me->{_FLAP_Bytes_Left} > 0) {
				if($Me->{_FLAP_SubHeader_Bytes_Left} > 0) {
					push @{$Me->{_FLAP_Sub_Header}}, $Packet[$i];
					$Me->{_FLAP_SubHeader_Bytes_Left}--;
					if (!$Me->{_FLAP_SubHeader_Bytes_Left}) {
						my (@HeaderPacket);
						@HeaderPacket = @{$Me->{_FLAP_Sub_Header}};
						$Me->{_FLAP_In_progress}{Family_ID}	 = _bytes_to_int(\@HeaderPacket, 0, 2);
						$Me->{_FLAP_In_progress}{Sub_ID}		= _bytes_to_int(\@HeaderPacket, 2, 2);
					}
				}
				push (@{$Me->{_FLAP_In_progress}{Data_Load}}, $Packet[$i]);

				$Me->{_FLAP_Bytes_Left}--;

				if ($Me->{_FLAP_Bytes_Left} <= 0) {
					#end the FLAP, and move it to the Queue..
					push(@{$Me->{_Incoming_Queue}}, $Me->{_FLAP_In_progress});
					$Me->{_FLAP_In_progress} = undef;
					$Me->{_FLAP_Header} = [];
					$Me->{_FLAP_Sub_Header} = [];
					$Me->{_FLAP_Bytes_Left} = 0;
					$Me->{_FLAP_SubHeader_Bytes_Left} = 4;
					$Me->{_FLAP_Header_Bytes_Left} = 6;
				}
				next;
			}

			#it's a new FLAP.. or part of new....
			# _print_packet($RawPacket, ());
				# print ".",$Me->{_FLAP_Header_Bytes_Left};

			if($Me->{_FLAP_Header_Bytes_Left} > 0) {
				push @{$Me->{_FLAP_Header}}, $Packet[$i];
				$Me->{_FLAP_Header_Bytes_Left}--;
				next if $Me->{_FLAP_Header_Bytes_Left};
			}

			my (@HeaderPacket);
			@HeaderPacket = @{$Me->{_FLAP_Header}};
			if($HeaderPacket[0] != 42 ) {
				$Me->SetError("Received Data Missaligned!");
				return;
			}

			$Me->{_FLAP_In_progress}{Channel_ID}	= _bytes_to_int(\@HeaderPacket, 1, 1);
			$Me->{_FLAP_In_progress}{Sequence_ID}	= _bytes_to_int(\@HeaderPacket, 2, 2);
			$Me->{_FLAP_In_progress}{Data_Size}	 = $Me->{_FLAP_Bytes_Left} = _bytes_to_int(\@HeaderPacket, 4, 2);
			# $Me->{_FLAP_In_progress}{Family_ID}	 = _bytes_to_int(\@HeaderPacket, 6, 2);
			# $Me->{_FLAP_In_progress}{Sub_ID}		= _bytes_to_int(\@HeaderPacket, 8, 2);

			# $i--;
		}
	}
}

sub Deal_With_FLAPs
{
	my($Me) = @_;
	foreach (@{$Me->{_Incoming_Queue}}) {
		if ($_->{Channel_ID} == 1) {
			my $ID = $_->{Family_ID}.":".$_->{Sub_ID};
			#login system message, deal with it..
			if ( exists $_New_Connection_Nefotiation_Codes{$_->{Sub_ID}} ) {
				# print "Found Connection Event, Dealing with it,,\n";
				&{$_New_Connection_Nefotiation_Codes{$_->{Sub_ID}}}($Me, $_);
			}

		} elsif ($_->{Channel_ID} == 2) {
			#This is a non critical FLAP. so decode, and pass to a hook if there is one..
			my $ID = $_->{Family_ID}.":".$_->{Sub_ID};

				print "zIncoming..($ID)\n" if $Me->{_Debug};
				_print_packet($_->{Data_Load}, ()) if $Me->{_Debug};

			if (exists $Me->{_Hooks}{$ID} ) {

				#decode the Sub_ID etc..
				print "can't run sub!![$ID]\n" if ( !(exists $_Srv_Decoder{$ID}) );
				print ">>> $ID\n" if $Me->{_Debug};

				my ($Refined);

				$Refined = &{$_Srv_Decoder{$ID}}($Me, $_)	if ( exists $_Srv_Decoder{$ID} );

				if((!exists $Refined->{MessageType}) 
					|| ($Refined->{MessageType} eq ''))
				{
					$Refined->{MessageType} = "$ID";
				}
				#run the Hook..
				&{$Me->{_Hooks}{$ID}}($Me, $Refined);
			} elsif ($Me->{_Auto_Login}) {
				&{$_Srv_Decoder{$ID}}($Me, $_)	if ( exists $_Srv_Decoder{$ID} );
			} elsif ($Me->{_Debug}) {
				print "zzzIncoming..\n" if $Me->{_Debug};
				print "[".$_->{Channel_ID}."][".$_->{Sequence_ID}."][".$_->{Data_Size}."][".$_->{Family_ID}."][".$_->{Sub_ID}."]\n" if $Me->{_Debug};
				_print_packet($_->{Data_Load}, ()) if $Me->{_Debug};
			}
		} elsif ($_->{Channel_ID} == 4) {
			# print "Found DisConnection Event, Dealing with it,,\n";
			print "." unless $Me->{_LoggedIn};
			my $ret = &_Disconnection_Nefotiation($Me, $_);
			return if($ret);
		} elsif ($_->{Channel_ID} == 5) {
			print ">> im alive! <<\n";
		} else {
			#this is an error type message..
		}

	}
	$Me->{_Incoming_Queue} = [];
}

sub Send_Outgoing
{
	my($Me) = @_;
	my($Chan, $Data_Size, @Header, $Raw_Data);

	foreach (@{$Me->{_Outgoing_Queue}}) {

		if ($_->{Channel_ID}){$Chan = $_->{Channel_ID};} else {$Chan = 2;}
		$Data_Size = @{$_->{Data_Load}};

		@Header = (42, $Chan);

		$Me->{_Seq_Num}++;
		$Me->{_Seq_Num} = 0 if $Me->{_Seq_Num} > 65535;

		push(@Header, _int_to_bytes(2, $Me->{_Seq_Num}));
		push(@Header, _int_to_bytes(2, $Data_Size));

		foreach (@Header)
		{
			$Raw_Data .= chr($_);
		}

		foreach (@{$_->{Data_Load}})
		{
			$Raw_Data .= chr($_);
		}

		print "Outgoing..\n" if $Me->{_Debug};
		_print_packet(\@Header, \@{$_->{Data_Load}}) if $Me->{_Debug};

	}

	#send them all off..
	if ($Raw_Data) {
		my $res = $Me->{_Socket}->send($Raw_Data);
	}

	$Me->{_Outgoing_Queue} = [];
}

#########################
### Private functions ###
#########################

#These functions should only ever be run from within the ICQ object..


sub xml_sub
{
	my $char = shift;
	return '&amp;' if($char eq '&');
	return '&lt;' if($char eq '<');
	return '&gt;' if($char eq '>');
	return '&quot;' if($char eq '"');
	return '&apos;' if($char eq "'");
	return $char;
}

sub xml_escape
{
	my $s = shift;
	$s=~s/([&<>"'])/&xml_sub($1)/eg;
	return $s;
}



# _bytes_to_int(array_ref, start, bytes)
#
# Converts the byte array referenced by <array_ref>, starting at offset
# <start> and running for <bytes> values, into an integer, and returns it.
# The bytes in the array must be in little-endian order.
#
# _bytes_to_int([0x34, 0x12, 0xAA, 0xBB], 0, 2) == 0x1234
# _bytes_to_int([0x34, 0x12, 0xAA, 0xBB], 2, 1) == 0xAA

sub _endian_bytes_to_int
{
	my ($array, $start, $bytes) = @_;
	my ($ret);

	$ret = 0;
	for (my $i = $start+$bytes-1; $i >= $start; $i--) {
		$ret <<= 8;
		$ret |= ($array->[$i] or 0);
	}

	return $ret;
}

sub _bytes_to_int
{
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
# returned. The array is in little-endian order.
#
# _int_to_bytes(2, 0x1234) == (0x34, 0x12)
# _int_to_bytes(2, 0x12345) == (0x45, 0x23)

sub _int_to_endian_bytes
{
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
# returned. The array is not little-endian order.
#
# _int_to_bytes(2, 0x1234) == (0x12, 0x34)
# _int_to_bytes(2, 0x12345) == (0x12, 0x34)

sub _int_to_bytes
{
	my ($bytes, $val) = @_;
	my (@ret);
	$val = 0 if not defined $val;
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

sub _str_to_bytes
{
	my ($string) = @_;
	my (@ret);

	# the ?: keeps split() from complaining about undefined values
	foreach (split(//, defined($string) ? $string : '')) {
		push @ret, ord($_);
	}
	return @ret;
}

sub _bytes_to_lnts
{
	my ($array, $start) = @_;
	my $DataLength = _endian_bytes_to_int($array, $start ,2);
	my $text = _bytes_to_str($array,$start+2 ,$DataLength-1);
	return $text;
}

sub _str_to_lnts
{
	my ($string) = (@_);
	my (@ret);
	push(@ret, _int_to_endian_bytes(2, length($string)+1));
	push(@ret, _str_to_bytes($string));
	push(@ret, _int_to_bytes(1, 0x00));

	return @ret;
}

sub _str_to_bws
{
	my ($string) = (@_);
	my (@ret);
	push(@ret, _int_to_bytes(2, length($string)));
	push(@ret, _str_to_bytes($string));

	return @ret;
}



# _uin_to_buin(str, add_zero)
#
# Converts <str> into an array of bytes and returns it.
#
# _str_to_bytes('foo')	 == ('f', 'o', 'o')

sub _uin_to_buin
{
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


sub _bytes_to_str
{
	# thanks to Dimitar Peikov for the fix
	my ($array, $start, $bytes) = @_;
	my ($ret);

	$ret = '';
	for (my $i = $start; $i < $start+$bytes; $i++) {
		$ret .= ($array->[$i] ne '') ? chr($array->[$i]) : '';
	}

	return $ret;
}

sub _bytes_to_ds
{
	# thanks to Dimitar Peikov for the fix
	my ($array, $start) = @_;
	my ($ret);

	my $bytes = _endian_bytes_to_int($array, $start, 4);
	$start += 4;

	$ret = '';
	for (my $i = $start; $i < $start+$bytes; $i++) {
		$ret .= ($array->[$i] ne '') ? chr($array->[$i]) : '';
	}

	return ($ret, $start + $bytes) ;
}




# print_packet(Header_packet_ref, Body_packet_ref)
#
# Dumps the ICQ packet contained in the byte array referenced by
# <packet_ref> to STDOUT.

sub _print_packet
{
	my ($Header, $packet) = @_;
	my ($Counter, $TLine);

	foreach (@$Header) {
		$Counter++;

		print sprintf("%02X ", $_);

		if ($_ >= 32) {
			$TLine .= chr($_);
		} else {
			$TLine .= ".";
		}

		if ($Counter % 16 == 0) {
			print "  ".$TLine."\n";
			$TLine = '';
		}
	}
	while ($Counter > 16){$Counter -=16}

	if (16 - $Counter > 1 && $Counter > 0) {
		foreach (1..(16 - $Counter)) {
			print "   ";
		}
		print "  ".$TLine."\n";
	}
	$TLine ='';
	$Counter =0;

	foreach (@$packet) {
		$Counter++;

		print sprintf("%02X ", $_);

		if ($_ >= 32) {
			$TLine .= chr($_);
		} else {
			$TLine .= ".";
		}

		if ($Counter % 16 == 0) {
			print "  ".$TLine."\n";
			$TLine = '';
		}
	}
	while ($Counter > 16){$Counter -=16}

	if (16 - $Counter > 1 && $Counter > 0) {
		foreach (1..(16 - $Counter)) {
			print "   ";
		}
		print "  ".$TLine."\n";
	}
	print "\n";
}

# _Password_Encrypt(Password_String)
# Encrypts the password for sending to the server using a simple XOR "encryption" method
sub _Password_Encrypt
{
	my ($Password) = @_;
	my ($FinishedString);

	my @Pass = split (//, $Password);

	foreach (@Pass) {
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

#
# Encryption function for direct connection
#

sub Encrypt
{
	my($aref) = @_;
	my $size = @{$aref};
	my @out = ();
	push @out, _int_to_endian_bytes(2,$size+1);
	push @out, _int_to_endian_bytes(1,0x02);
	my $M1 = (rand(900) % (($size < 255 ? $size : 255)-10))+10;
	my $X1 = ${$aref}[$M1] ^ 0xff;
	my $X2 = rand(900) % 220;
	my $X3 = $client_check_data[$X2] ^ 0xFF;
	my $B1 = (${$aref}[4]<<24)|(${$aref}[6]<<16)|(${$aref}[4]<<8)|(${$aref}[6]);

	my $check = ($M1 << 24) | ($X1 << 16) | ($X2 << 8) | $X3;

	$check ^= $B1;
	push @out, _int_to_endian_bytes(4, $check);
	my $key = Math::BigInt->new(1734701672);
	my $tmp = Math::BigInt->new(4294967296);
	$key *= $size;
	$key += $check;
	$key = $key->bmod($tmp);
	splice @{$aref},0,4;
	my ($i,$k,$hex,$j);
	for($i=4; $i<int (($size+3)/4); $i+=4) {
		$hex = $key + $client_check_data[$i&0xFF];
		for($j=0;$j<4;$j++)
		{
			$k = shift @{$aref};
			push @out, ($k ^ (($hex>>(8*$j))&0xFF));
		}
	}
	push @out,@{$aref};
	return @out;
}



#
# Decryption function for direct connection
#
sub Decrypt
{
	my($aref) = @_;
	my @out;
	my ($j, $k, $i, $hex);
	my $correction = 3; #v7
	my $size = @{$aref} - $correction;

	my $t1 = shift @{$aref};


	push @out, $t1;
	$t1 = shift @{$aref};
	push @out, $t1;
	$t1 = shift @{$aref};
	push @out, $t1;
	my $check = _endian_bytes_to_int($aref, 0, 4);
	my $check2 = _bytes_to_int($aref, 0, 4);
	splice @{$aref},0,4;
	push @out, _int_to_endian_bytes(4, $check);
	my $key = Math::BigInt->new(1734701672);
	my $tmp = Math::BigInt->new(4294967296);
	$key *= $size;
	$key += $check;
	$key = $key->bmod($tmp);

	for($i=4; $i<int (($size+3)/4); $i+=4) {
		$hex = $key + $client_check_data[$i&0xFF];
		for($j=0;$j<4;$j++)
		{
			$k = shift @{$aref};
			my $zz =($k ^ (($hex>>(8*$j))&0xFF));
			push @out, $zz;
		}
	}
	push @out, @{$aref};
	my $B1 = ($out[4+$correction]<<24) | ($out[6+$correction]<<16) | ($out[4+$correction]<<8) | ($out[6+$correction]);
	# special decryption
	$B1 ^= $check;

	# validate packet
	my $M1 = ($B1 >> 24) & 0xFF;
	if($M1 < 10 || $M1 >= $size) { return (); }

	my $X1 = $out[$M1+$correction] ^ 0xFF;
	if((($B1 >> 16) & 0xFF) != $X1) { return (); }

	my $X2 = (($B1 >> 8) & 0xFF);
	if($X2 < 220) {
		my $X3 = $client_check_data[$X2] ^ 0xFF;
		if(($B1 & 0xFF) != $X3) { return (); }
	}
	# for($i=0;$i<@out;$i++)
	# {
		# ${$aref}[$i] = $out[$i];
	# }
	return @out;
}


# _Make_SNAC_Header(Comand_Family, Sub_Family, FlagA, FlagB, RequestID)
#makes the SNAC header which has to be at the top of every command..

sub _Make_SNAC_Header
{
	my($Family, $Sub_Family, $FlagA, $FlagB, $RequestID) = @_;
	my (@Header);

		@Header = _int_to_bytes(2, $Family);
	push(@Header, _int_to_bytes(2, $Sub_Family));
	push(@Header, _int_to_bytes(1, $FlagA));
	push(@Header, _int_to_bytes(1, $FlagB));
	push(@Header, _int_to_bytes(4, $RequestID));

	return @Header;
}


sub base64encode
{
	my $w = shift;
	my $l = length($w);
	my $res = '';

	my @base64 = qw(A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
					a b c d e f g h i j k l m n o p q r s t u v w x y z
					0 1 2 3 4 5 6 7 8 9 + /);
	while($w =~ /(..?.?)/g) {
		my $b = $1;
		while(length($b)<3)
		{
			$b .= '\x00';
		}
		my @data = split //,$b;
		my $int=0;
		my $mult = 0x10000;
		foreach (@data)
		{
			$_ = ord;
		}

		$int = $data[0]*0x10000 + $data[1]*0x100 + $data[2];

		my $i = 4;
		my @b64 = ('','','','');
		while($i)
		{
			$b64[$i] = $base64[$int % 0x40];
			$int = ($int - $int % 0x40) / 0x40;
			if((@data == 1) && ( $i > 2)) {
				$b64[$i] = '=';
			}
			if((@data == 2) && ( $i > 3)) {
				$b64[$i] = '=';
			}
			$i--;
		}
		$res .= join ('',@b64);

	}
	return $res;
}

# this function takes a tagged string (like the server sends..) and
# breaks it up into it's parts...

sub _Decode_Tagged_Text
{
	my($String, $Details) = @_;
	my($Key, $Data, $i);
	$String =~ s/\n/ /g;
	if($String =~ /<([^>]*)>/i) {
		$Details->{MessageType} = $1;
		if($String =~ /<$Details->{MessageType}>(.*)<\/$Details->{MessageType}>?/i) {
			my $keys = $1;
			while($keys =~ /<(.*?)>(.*?)<\/.*?>/g)
			{
				$Details->{$1} = $2;
			}
		} else {
			$Details->{MessageType} = 'Invalid data!';
		}
	} else {
		$Details->{MessageType} = 'Invalid tagged message';
	}
	return ($Details);
}

%_Error_Codes = (
	1 => "Bad UIN",
	5 => "Password mismatch",
	24 => "Connection rate exceeded",
	29 => "Trying to reconnect too fast"
);



#####################
### TLV functions ###
#####################

# TLV (Type, Length, Value) is the way much of the data is sent an received
# The Data below contains the definitions of the Types, their lengths, and what kind
# of data is to be expected (eg strings or ints etc..)
# Also has the _Write_TLV and _Read_TLV functions..

#definitions for the TLVs types being sent from the server..
#The first digit (2 or 4) denotes the FLAP's Chan
%_TLV_IN = (
	2 => {	User_Class =>		0x01,#!?????
#		Signup_Date =>		0x02,#! doesn't really work for ICQ, set to date of login, 1 sec before normal login date..
		SignOn_Date =>		0x03,#!
		Unknown00 =>		0x04,#! ??
		Encoded_Message =>	0x05,#!
		Encoded_MessageOld =>	0x02,#!
		Status =>		0x06,#!
		Ip_Address =>		0x0a,#! in 4 byte format..
		Web_Address =>		0x0b,#!
		LANInfo =>		0x0c,#! (long like 25 bytes..)
		CapabilityInfo =>	0x0d,#! ???
		Time_Online =>		0x0f, #!
		SomeNewTLV =>		0x13,
		},
	4 => {  UIN =>			0x01,#!
		HTML_Address =>		0x04,#!
		Server_And_Port =>	0x05,#!
		Connection_Cookie =>	0x06,#!
		Error_Code =>		0x08,#!
		Dual_User_Online =>	0x09,
		},

	);

#definitions for the TLVs types being sent from us to the server..
#The first digit (1 or 2) denotes the FLAP's Chan
%_TLV_OUT = (
	1 => {	UIN =>			0x01,#!
		Password =>		0x02,#!
		ClientProfile =>	0x03,#!
		User_Info =>		0x05,
		Connection_Cookie =>	0x06,#!
		CountryCode =>		0x0e,#!
		Language =>		0x0f,#!
		ClientBuildMinor =>	0x14,#!
		ClientType =>		0x16,#!
		ClientVersionMajor =>	0x17,#!
		ClientVersionMinor =>	0x18,#!
		ClientICQNumber =>	0x19,#!
		ClientBuildMajor =>	0x1a #!
	},
	2 => {	Status =>			0x06,#!
		ErrorCode =>			0x08,#!????
		DirectConnnectionInfo =>	0x0c#!????
	}
);

#if the TLV is a number, we define the number of bytes to use..(note all numbers are their decimal value, not hex)
# 1000 denotes a "raw" data input, and is encoded differently..
%_TLV_Length_O = (
	1 => {	6 =>	1000,
		20 =>	4,
		22 =>	2,
		23 =>	2,
		24 =>	2,
		25 =>	2,
		26 =>	2
	},
	2 => {	6 =>	4,
		8 =>	2,
	},
);

#This defines the type of data we expect coming in, the codes are as follows..
# 0 or no entry = String
# 1 = Int
# 2 = Raw (obtains the data still as a string of numbers separated by spaces)
# 3 = IP

%_TLV_Length_I = (
	2 => {	1 =>	1,
		2 =>	2,
		3 =>	1,
		4 =>	1,
		5 =>	2,
		6 =>	1,
		10 =>	3,
		12 =>	0x25,
		15 =>	1,
		19 =>	2,
	},
	4 => {	8 =>	1,
		6 =>	2,
	},
);

# _Write_TLV(Message_Channel, Type_Value, Info_To_Encode)
#
# This creates an packet array ready for sending to the server, containing the given data

sub _Write_TLV
{
	my($Chan, $Value, $Infomation) = @_;
	my(@Data);

	$Value = $_TLV_OUT{$Chan}{$Value} if (exists $_TLV_OUT{$Chan}{$Value});
	@Data = _int_to_bytes(2, $Value);
	if (exists $_TLV_Length_O{$Chan}{$Value}) {
		if ($_TLV_Length_O{$Chan}{$Value} == 1000) {
			#get it as an array!
			my @Cookie = split(/ /, $Infomation);
			my $CLength = @Cookie;
			push(@Data, _int_to_bytes(2, $CLength));
			push(@Data, @Cookie);
		} else {
			#their a number, and need a set byte size..
			push(@Data, _int_to_bytes(2, $_TLV_Length_O{$Chan}{$Value}));
			push(@Data, _int_to_bytes($_TLV_Length_O{$Chan}{$Value}, $Infomation));
		}
	} else {
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

sub _Read_TLV
{
	my($Array, $Chan, $Start, $Details, $Max) = @_;
	my($i, $ArrayLength, $DataType, $DataLength, $DataTypeName);

	$ArrayLength = @$Array;

	$Start or $Start = 0;
	$Max or $Max = 100000;

	for ($i = $Start; $i <$ArrayLength;) {

		#only get up to the max number of TVLs
		$Max or last;
		$Max--;

		#read in the Data Type/length..
		$DataType = _bytes_to_int ($Array, $i, 2);
		$DataLength = _bytes_to_int ($Array, $i+2, 2);
		$i += 4;

		#find the name of this data type..
		$DataTypeName = $DataType;
		foreach (keys %{$_TLV_IN{$Chan}}) {
			$DataTypeName = $_ if ($_TLV_IN{$Chan}{$_} == $DataType);
		}

		if( exists $_TLV_Length_I{$Chan}{$DataType}) {
			if ($_TLV_Length_I{$Chan}{$DataType} == 2) {
				#get it as an array!
				for (my $p=0; $p < $DataLength; $p++) {
					$Details->{$DataTypeName} .= $Array->[$i+$p]." ";
				}
				chop $Details->{$DataTypeName};
			} elsif ($_TLV_Length_I{$Chan}{$DataType} == 3) {
				#get it as IP address
				if ($DataLength != 4) {
					print "Argh, This an't an IP!!!\n";
				} else {
					$Details->{$DataTypeName} = _bytes_to_int ($Array, $i, 1)."."._bytes_to_int ($Array, $i+1, 1)."."._bytes_to_int ($Array, $i+2, 1)."."._bytes_to_int ($Array, $i+3, 1);
				}

			} elsif ($_TLV_Length_I{$Chan}{$DataType} == 1) {
				#we're getting a number...
				$Details->{$DataTypeName} = _bytes_to_int ($Array, $i, $DataLength);
			} else {
				$Details->{$DataTypeName} = _bytes_to_str ($Array, $i, $_TLV_Length_I{$Chan}{$DataType});
			}

		} else {
			$Details->{$DataTypeName} = _bytes_to_str ($Array, $i, $DataLength);
		}
		$i +=$DataLength;
	}
	return ($Details, $i);
}

sub BuildGenericAck
{
	my ($type, $flags, $seqnum, $astatus) = @_;
	$astatus = 0 unless defined $astatus;
	my @Ack = ();
	push(@Ack, _int_to_endian_bytes(4, 0));
	push(@Ack, _int_to_endian_bytes(2, 0x07da));
	push(@Ack, _int_to_endian_bytes(2, 0x000e));
	push(@Ack, _int_to_endian_bytes(2, $seqnum));
	push(@Ack, _int_to_endian_bytes(4, 0));
	push(@Ack, _int_to_endian_bytes(4, 0));
	push(@Ack, _int_to_endian_bytes(4, 0));
	push(@Ack, $type);
	push(@Ack, $flags);
	push(@Ack, _int_to_endian_bytes(2, $astatus)); # status
	push(@Ack, _int_to_endian_bytes(2, 0x0000)); # priority
	return @Ack;

}

sub AcceptFile
{
	my ($Me, $connection) = @_;
	my @Ack;
	my $type = $connection->{type};
	my $flags = $connection->{flags};
	my $seqnum = $connection->{seqnum};
	# Accept ack
	my $port = $Me->{_FilePort};
	@Ack = BuildGenericAck($type,$flags,$seqnum);
	push(@Ack, _int_to_endian_bytes(1, 0x01));
	push(@Ack, _int_to_bytes(4, $port));
	push(@Ack, _int_to_endian_bytes(2, 0x0000));
	push(@Ack, _str_to_lnts(""));
	push(@Ack, _int_to_bytes(4, 0x12345678));
	push(@Ack, _int_to_endian_bytes(4, $port));
	@Ack = Encrypt(\@Ack);
	push @{$connection->{ToSend}},@Ack;

}

sub RejectFile
{
	my ($Me, $connection) = @_;
	my $type = $connection->{type};
	my $flags = $connection->{flags};
	my $seqnum = $connection->{seqnum};
	my @Ack;
	@Ack = BuildGenericAck($type,$flags,$seqnum,1);
	push(@Ack, _str_to_lnts("No files!"));
	push(@Ack, _int_to_endian_bytes(4, 0xffffffff));
	push(@Ack, _int_to_endian_bytes(3, 0x000100));
	push(@Ack, _int_to_endian_bytes(4, 0xffffffff));
	push(@Ack, _int_to_endian_bytes(4, 0xffffffff));
	@Ack = Encrypt(\@Ack);
	push @{$connection->{ToSend}},@Ack;
}

sub GetURLMessage
{
	my ($array, $start) = @_;
	my $DataLength = _bytes_to_int ($array, $start, 2);
	my $data = _bytes_to_str($array, $start+2, $DataLength);
	my @rez = split /\xfe/,$data;
	return @rez;
}

1;

