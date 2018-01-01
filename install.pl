#!/usr/bin/perl

use Getopt::Long;

my $o_help = '';
my $o_prefix = '';       
my $o_bindir = '';
my $o_mandir = '';

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

($err = `cp vicq $bindir`) and fail($err);
($err = `pod2man vicq --section=1 --release="vICQ 0.3" --center="vICQ manual page" | gzip -c >  $mandir/man1/vicq.1.gz`) and &fail($err);

sub fail
{
	my $msg = shift;
	print "Installatioon failed: $msg\n";
	exit(1);
}
