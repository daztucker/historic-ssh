#!/usr/local/bin/perl -w
# -*- perl -*-
######################################################################
# make-ssh-known-hosts.pl -- Make ssh-known-hosts file
# Copyright (c) 1995 Tero Kivinen
# All Rights Reserved.
#
# Make-ssh-known-hosts is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY.  No author or distributor accepts
# responsibility to anyone for the consequences of using it or for
# whether it serves any particular purpose or works at all, unless he
# says so in writing.  Refer to the GNU General Public License for full
# details.
#
# Everyone is granted permission to copy, modify and redistribute
# make-ssh-known-hosts, but only under the conditions described in
# the GNU General Public License.  A copy of this license is supposed to
# have been given to you along with make-ssh-known-hosts so you can
# know your rights and responsibilities.  It should be in a file named
# gnu-COPYING-GPL.  Among other things, the copyright notice and this notice
# must be preserved on all copies.
######################################################################
#         Program: make-ssh-known-hosts.pl
#	  $Source: /p/shadows/CVS/ssh/make-ssh-known-hosts.pl,v $
#	  Author : $Author: ylo $
#
#	  (C) Tero Kivinen 1995 <Tero.Kivinen@hut.fi>
#
#	  Creation          : 19:52 Jun 27 1995 kivinen
#	  Last Modification : 10:51 Jul 14 1995 kivinen
#	  Last check in     : $Date: 1995/08/29 22:37:39 $
#	  Revision number   : $Revision: 1.3 $
#	  State             : $State: Exp $
#	  Version	    : 1.214
#	  Edit time	    : 63 min
#
#	  Description       : Make ssh-known-host file from dns data.
#
#	  $Log: make-ssh-known-hosts.pl,v $
# Revision 1.3  1995/08/29  22:37:39  ylo
# 	Now uses GlobalKnownHostsFile and UserKnownHostsFile.
#
# Revision 1.2  1995/07/15  13:26:37  ylo
# 	Changes from kivinen.
#
# Revision 1.1.1.1  1995/07/12  22:41:05  ylo
# Imported ssh-1.0.0.
#
#
#
# If you have any useful modifications or extensions please send them to
# Tero.Kivinen@hut.fi
#
######################################################################
# initialization

require 5.000;
use Getopt::Long;
use FileHandle;
use POSIX;

$command_line = "$0 ";
foreach $a (@ARGV) {
    $command_line .= $a . " ";
}

STDERR->autoflush(1);
$debug = 5;
$nslookup = "nslookup";
$ping="ping";
$pingpreoptions=undef;
$pingpostoptions=undef;
$ssh="ssh -x -a -o 'FallBackToRsh no' -o 'GlobalKnownHostsFile /dev/null' -o 'UserKnownHostsFile /tmp/ssh_known_hosts'";
$sshdisablepasswordoption="-o 'PasswordAuthentication no'";
$defserver = '';
$bell='\a';
$public_key = '/etc/ssh_host_key.pub';
if (!defined($ENV{'HOME'})) {
    ($junk, $junk, $junk, $junk, $junk, $junk, $junk, $dir, $junk) =
	getpwuid($<);
    $ENV{'HOME'} = $dir;
}
$private_ssh_known_hosts = "/tmp/ssh_known_hosts";
unlink($private_ssh_known_hosts);
$timeout = 60;
$passwordtimeout = undef;
$trustdaemon = 0;
$domainnamesplit = 0;

######################################################################
# Parse options

GetOptions("initialdns=s", "server=s", "subdomains=s",
	   "debug=i", "timeout=i", "passwordtimeout=i",
	   "trustdaemon", "domainnamesplit", "silent",
	   "nslookup=s",
	   "ping=s", "pingpostoptions=s", "pingpreoptions=s",
	   "ssh=s")
    || die "Getopt : $!";

if (defined($opt_initialdns)) { $defserver = $opt_initialdns; }

if (defined($opt_server)) { $server = $opt_server; }

if (defined($opt_subdomains)) { @subdomains = split(/,/, $opt_subdomains); }

if (defined($opt_debug)) { $debug = $opt_debug; }

if (defined($opt_timeout)) { $timeout = $opt_timeout; }

if (defined($opt_passwordtimeout)) {
    $passwordtimeout = $opt_passwordtimeout;
    $sshdisablepasswordoption = '';
}

if (defined($opt_trustdaemon)) { $trustdaemon = $opt_trustdaemon; }

if (defined($opt_domainnamesplit)) { $domainnamesplit = $opt_domainnamesplit; }

if (defined($opt_silent)) { $bell = ''; }

if (defined($opt_nslookup)) { $nslookup = $opt_nslookup; }

if (defined($opt_ping)) { $ping = $opt_ping; }

if (defined($opt_pingpostoptions)) { $ping = $opt_pingpostoptions; }

if (defined($opt_pingpreoptions)) { $ping = $opt_pingpreoptions; }

if (defined($opt_ssh)) { $ssh = $opt_ssh; } else {
    $ssh = "$ssh $sshdisablepasswordoption";
}

if ($#ARGV == 0) {
    $domain = "\L$ARGV[0]\E";
    $grep_yes = '.*';
    $grep_no = '^$';
} elsif ($#ARGV == 1) {
    $domain = "\L$ARGV[0]\E";
    $grep_yes = $ARGV[1];
    $grep_no = '^$';
} elsif ($#ARGV == 2) {
    $domain = "\L$ARGV[0]\E";
    $grep_yes = $ARGV[1];
    $grep_no = $ARGV[2];
} else {
    print(STDERR "$0 [--initialdns initial_dns_server] [--server dns_server] [--subdomains sub.sub.domain,sub.sub,sub,] [--debug debug_level] [--timeout exec_timeout_in_secs] [--passwordtimeout timeout_for_password_in_secs] [--trustdaemon] [--domainnamesplit] [--silent] [--nslookup path_to_nslookup] [--ping path_to_ping] [--pingpostoptions string] [--pingpreoptions string] [--ssh path_to_ssh] full.domain [ host_info_take_regexp [ host_info_remove_regex ]]\n");
    exit(1);
}

######################################################################
# Check that ping and ssh programs exists

if (system("$ping > /dev/null 2>&1") != 256) {
    print(STDERR "Error: Could not run ping program ($ping): $!\nError: Try giving the path to it with --ping option\n");
    exit(1);
}

if (!defined($pingpreoptions) && !defined($pingpostoptions)) {
    if (system("$ping localhost 1 1 > /dev/null 2>&1") == 0) {
	$pingpreoptions = '';
	$pingpostoptions = '1 1';
    } elsif (system("$ping -c 1 localhost > /dev/null 2>&1") == 0) {
	$pingpreoptions = '-c 1';
	$pingpostoptions = '';
    } else {
	print(STDERR "Error: Could not find out the usage of ping program ($ping): $!\nError: Try giving the pre and post options with --pingpostoptions and pingpreoptions option\n");
	exit(1);
    } 
} elsif (!defined($pingpreoptions)) {
    $pingpreoptions = '';
} elsif (!defined($pingpostoptions)) {
    $pingpostoptions = '';
}

debug(20, "Ping command: $ping $pingpreoptions hostname $pingpostoptions");

if (system("$ssh > /dev/null 2>&1 ") != 256) {
    print(STDERR "Error: Could not run ssh program ($ssh): $!\nError: Try giving the path to it with --ssh option\n");
    exit(1);
}

######################################################################
# Generate subdomains list

if (!$domainnamesplit) {
    debug(6, "Auto splitting host entries");
} elsif (!defined(@subdomains)) {
    debug(6, "Generating subdomain list");
    
    # split domain to pieces
    @domain_pieces = split(/\./, $domain);
    
    # add empty domain part
    push(@subdomains, '');
    
    # add rest parts, except the one before full domain name
    $entry='';
    for(; $#domain_pieces > 1; ) {
	$entry .= "." . shift(@domain_pieces);
	push(@subdomains, $entry);
    }
    
    # add full domain name
    push(@subdomains, ".$domain");
    debug(5, "Subdomain list: " . join(',', @subdomains));
} else {
    debug(5, "Using given subdomain list:" . join(',', @subdomains));
}

######################################################################
# finding SOA entry for domain

if (!defined($server)) {
    debug(6, "Finding DNS database SOA entry");
    open(DNS, "$nslookup -type=soa $domain $defserver 2>&1 |") ||
	die "Error: Could not start nslookup to find SOA entry for $domain : $!\nError: Try giving the path to it with --nslookup option\n";
    
    while (<DNS>) {
	if (/\s+(\S+)\s*=\s*(.*)\s*$/) {
	    $field = $1;
	    $data = $2;
	    debug(10, "Found field $field = $data");
	    if ($field =~ /origin/i) {
		$server = $data;
	    }
	}
    }
    close(DNS);
    
    if (!defined($server)) {
	print(STDERR "Error: Could not find DNS SOA entry from default dns server\nError: Try giving the initial nameserver with --initialdns option\n");
	exit(1);
    } else {
	debug(5, "DNS server found : $server");
    }
} else {
    debug(5, "Using given DNS server : $server");
}

######################################################################
# Get DNS database list from server

debug(0, "Getting DNS database from server $server");
open(DNS, "echo ls -d $domain | nslookup - $server 2>&1 |") ||
    die "Error: Could not start nslookup to make dns list : $!\nError: Try giving --nslookup option and telling the path to nslookup program\n";

$hostcnt = 0;
$cnamecnt = 0;
$lines = 0;
while(<DNS>) {
    $lines++;
    if (/^\s+(\S+)\s+(\S+)\s+(.*)\s*$/) {
	$host = "\L$1\E";
	$field = "\L$2\E";
	$data = "\L$3\E";
	debug(50, "Line = /$host/$field/$data/");
	if ($host !~ /\.$/) {
	    $host .= ".$domain";
	} else {
	    $host =~ s/\.$//g;
	}
	if ($field eq "a") {
	    if ($host =~ /$domain$/) {
		if (defined($host{$host})) {
		    $host{$host} .= ",$data";
		} else {
		    $host{$host} = "$data";
		    $hostcnt++;
		}
		debug(30, "$host A == $host{$host}");
	    }
	} elsif ($field eq "cname") {
	    if ($host =~ /$domain$/) {
		if (defined($cname{$data})) {
		    $cname{$data} .= ",$host";
		} else {
		    $cname{$data} = "$host";
		    $cnamecnt++;
		}
		debug(30, "$host CNAME $data");
	    }
	}
	if (!defined($hostdata{$host})) {
	    $hostdata{$host} = "$host\n$field=$data\n";
	} else {
	    $hostdata{$host} .= "$field=$data\n";
	}
    }
}
close(DNS);
debug(0, "Found $hostcnt hosts, $cnamecnt CNAMEs (total $lines lines)");

######################################################################
# Print header

($name, $junk, $junk, $junk, $junk, $junk, $gecos) = getpwuid($<);
$gecos =~ s/,.*$//g;

print(STDOUT "# This file is generated with make-ssh-known-hosts.pl using command line :\n");
print(STDOUT "# $command_line\n");
print(STDOUT "#\n");
print(STDOUT "# The script was run by $gecos ($name) at " . localtime() . "\n");
print(STDOUT "# using perl ($^X) version $].\n");
print(STDOUT "#\n");

######################################################################
# Loop through hosts and try to connect to hosts

foreach $i (sort (keys %host)) {
    debug(50, "Host = $i, Hostdata = $hostdata{$i}");
    if ($hostdata{$i} =~ /$grep_yes/im &&
	$hostdata{$i} !~ /$grep_no/im &&
	$i !~ /^localhost\./ &&
	$host{$i} !~ /^127.0.0.1$|^127.0.0.1,|,127.0.0.1$|,127.0.0.1,/) {
	debug(2, "Trying host $i");
	if (try_ping("$i")) {
	    $trusted = 1;
	    $err = 'Timeout expired';
	    $ssh_key = try_ssh("$i");
	    if (!defined($ssh_key)) {
		$ssh_key = find_host_from_known_hosts($i);
		$trusted = 0;
	    }
	    if (defined($ssh_key)) {
		if ($trusted) {
		    debug(2, "Ssh to $i succeded");
		} else {
		    debug(2, "Ssh to $i failed, using local known_hosts entry");
		}
		@hostnames = ();
		if (defined($cname{$i})) {
		    expand($i, \@hostnames, \@subdomains);
		    foreach $j (split(/,/, $cname{$i})) {
			expand($j, \@hostnames, \@subdomains);
		    }
		} else {
		    expand($i, \@hostnames, \@subdomains);
		}
		foreach $j (split(/,/, $host{$i})) {
		    push(@hostnames, $j);
		}
		$hostnames = join(',', (@hostnames));
		debug(4, "adding entries : $hostnames");
		$ssh_key =~ s/root@//i;
		if (!$trusted || $trustdaemon) {
		    print(STDOUT "# $hostnames $ssh_key\n");
		} else {
		    print(STDOUT "$hostnames $ssh_key\n");
		}
	    } else {
		debug(2, "ssh failed : $err");
	    }
	} else {
	    debug(2, "ping failed");
	}
    } else {
	debug(10, "Skipped host $i");
    }
}

unlink($private_ssh_known_hosts);
exit (0);

######################################################################
# try_ping -- try to ping to host and return 1 if success
# $success = try_ping($host);

sub try_ping {
    my($host) = @_;
    my($pid, $rin, $nfound, $tmout, $buf, $ret, $pos);
    
    $pid = open(PING, "$ping $pingpreoptions $host $pingpostoptions |");
    if ($pid == 0) {
	return undef;
    }

    $tmout = $timeout;
    $buf = '';
    $pos = 0;
    debug(10, "Starting ping select loop");
    while (1) {
	$rin = '';
	vec($rin, fileno(PING), 1) = 1;
	($nfound, $tmout) = select($rin, undef, undef, $tmout);
	
	# Timeout
	if ($nfound <= 0) {
	    debug(20, "Ping select timed out");
	    kill(9, $pid);
	    close(PING);
	    return 0;
	}
	# Read the junk
	$ret = sysread(PING, $buf, 256, $pos);
	
	# EOF or error
	if ($ret <= 0) {
	    # Yes, close the pipe and return status
	    close(PING);
	    debug(20, "Ping select closed status = $?, line = $buf");
	    return !($?);
	}
	$pos += $ret;
    }
}

######################################################################
# try_ssh -- try ssh connection to host and return ssh_key if success
# if failure return undef, and set $err string to contain error message.
# $ssh_key = try_ssh($host);

sub try_ssh {
    my($host) = @_;
    my($buf, $ret, $pos, $pid, $rin, $nfound, $tmout);

    $pid = open(SSH, "$ssh $host cat $public_key 2>&1 |");
    $err = undef;

    if ($pid == 0) {
	$err = "could not open ssh connection to host";
	return undef;
    }
    $ret = 1;
    $pos = 0;
    $buf = '';
    $tmout = $timeout;
    debug(10, "Starting ssh select loop");
  loop:
    while (1) {
	
	$rin = '';
	vec($rin, fileno(SSH), 1) = 1;
	($nfound, $tmout) = select($rin, undef, undef, $tmout);
	
	# Timeout
	if ($nfound <= 0) {
	    debug(20, "Ssh select timed out");
	    kill(9, $pid);
	    close(SSH);
	    $err = "Timeout expired";
	    return undef;
	}
	
	$ret = sysread(SSH, $buf, 256, $pos);
	# EOF or error
	if ($ret <= 0) {
	    # Yes, close the pipe and return
	    close(SSH);
	    debug(20, "Ssh select closed status = $?");
	    $err = "No reply from ssh";
	    return undef;
	}
	$pos += $ret;
	while ($buf =~ /^(.*)\n\r?([\000-\377]*)$/) {
	    $_ = $1;
	    $buf = $2;
	    $pos = length($buf);
	    debug(20, "Ssh select loop, line = \"$_\"");
	    if (/^connection.*refused/i) {
		$err = "connection refused";
	    } elsif (/^permission/i) {
		$err = "permission denied";
	    } elsif (/$public_key.*no\s+file/i) {
		$err = "$public_key file not found";
	    } elsif (/$public_key.*permission\s+denied/i) {
		$err = "$public_key file permission denied";
	    } elsif (/^\d+\s+\d+\s+\d/) {
		kill(9, $pid);
		close(SSH);
		return $_;
	    }
	    if (defined($err)) {
		kill(9, $pid);
		close(SSH);
		return undef;
	    }
	}
	if ($buf =~ /^password: $/i) {
	    if (defined($passwordtimeout)) {
		$tmout = $passwordtimeout;
		print(STDERR "$bell\n\rPassword: ");
		if ($tmout == 0) {
		    $tmout = undef;
		}
	    } else {
		$tmout = 0;
	    }
	    $buf = '';
	    $pos = 0;
	}
    }
}

######################################################################
# find_hosts_from_known_hosts -- find host key from private known_hosts file
# $ssh_key = find_host_from_known_hosts($host);

sub find_host_from_known_hosts {
    my($host) = @_;
    open(KNOWNHOSTS, "<$private_ssh_known_hosts") || return undef;
    while(<KNOWNHOSTS>) {
	@_ = split(/\s+/, $_);
	if ($_[0] =~ /^$host$|^$host,|,$host$/) {
	    shift(@_);
	    close(KNOWNHOSTS);
	    return join(' ', @_);
	}
    }
    close(KNOWNHOSTS);
    return undef;
}

######################################################################
# expand -- insert expanded hostnames to hostnames table
# expand($hostname, \@hostnames, \@subdomains);

sub expand {
    my($host, $hostnames, $subdomains) = @_;
    my($newhost, $sub, $entry);

    if (!$domainnamesplit) {
	my(@domain_pieces);
	
	# split domain to pieces
	@domain_pieces = split(/\./, $host);
    
	# add rest parts, except the one before full domain name
	$entry = shift(@domain_pieces);
	
	debug(20, "Adding autosplit entry $entry");
	push(@$hostnames, $entry);
	
	for(; $#domain_pieces > 1; ) {
	    $entry .= "." . shift(@domain_pieces);
	    debug(20, "Adding autosplit entry $entry");
	    push(@$hostnames, $entry);
	}
	# add full domain name
	debug(20, "Adding autosplit entry $host");
	push(@$hostnames, $host);
    } else {
	if ($host =~ /^(.*)$domain$/i) {
	    $newhost = $1;
	    $newhost =~ s/\.$//g;
	    foreach $sub (@$subdomains) {
		$entry = $newhost . $sub;
		$entry =~ s/^\.//g;
		if ($entry ne '') {
		    debug(20, "Adding entry $entry");
		    push(@$hostnames, $entry);
		}
	    }
	}
    }
}

######################################################################
# Print debug text
# debug(text_debug_level, string)

sub debug {
    my($level, $str) = @_;
    if ($debug > $level) {
	print(STDERR "$0:debug[$level]: $str\n");
    }
}

######################################################################
# make_perl_happy -- use some symbols, so perl doesn't complain so much
# make_perl_happy();

sub make_perl_happy {
    if (0) {
	print $FileHandle::ARG, $opt_silent;
    }
}

1;
