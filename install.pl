#!/usr/bin/perl
# $Id: install.pl,v 1.5 2002/01/07 12:31:47 gonzo Exp $

use Getopt::Long;

my $o_help = '';
my $o_prefix = '';       
my $o_bindir = '';
my $o_mandir = '';

my $subdir = $0;
$subdir =~ s/[^\/]*$//g;
$subdir .= '/' if ($subdir ne '');

print "Installing vICQ.pm...";
chdir "$subdir" . "Net/vICQ/" or die "$!";
$res = `./install.sh`;
if($res || ($? == -1))
{
	$res = "install.sh: $!" if ($? == -1);
	print "failed\n";
	print "Installation error:\n$res\n";
	exit;
}
chdir "../../";
print "done\n";

GetOptions ('prefix=s' => \$o_prefix, 'help' => \$o_help, 
			'bindir=s' => \$o_bindir, 'mandir=s' => \$o_mandir);

##
# Help
##

if($o_help)
{
	print "Usage: $0 [options]\n";
	print "Options:\n";
	print "--help                    print this message\n";
	print "--prefix=PREFIX           where vicq package should be installed\n"; 
	print "--bindir=DIR              where executable script should be instaled\n";
	print "--mandir=DIR              where manual should be instaled\n";
	exit(0);
}

my $prefix = $o_prefix || '/usr/local';
my $bindir = $o_bindir || $prefix . '/bin';
my $mandir = $o_mandir || $prefix . '/man';
my $mansection = $mandir . '/man1';

fail ("$bindir directory doesn't exist") unless -d $bindir;
fail ("$mandir directory doesn't exist") unless -d $mandir;

mkdir ("$mansection",0755) or fail("Can't create $mansection directory: $!") unless -d "$mansection";


($err = `cp vicq $bindir`) and fail($err);
($err = `pod2man vicq --section=1 --release="vICQ 0.3" --center="vICQ manual page" | gzip -c >  $mandir/man1/vicq.1.gz`) and &fail($err);
print "Instalation complete\n";
sub fail
{
	my $msg = shift;
	print STDERR "Installatioon failed: $msg\n";
	exit(1);
}
