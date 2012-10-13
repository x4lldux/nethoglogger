package Nethoglogger;

use v5.10.1;
use strict;
use warnings;

use AnyEvent;
use AnyEvent::Pcap;
use Unix::Lsof;
use JSON;
use Data::Printer;

our $VERSION = '0.01';

my $interval=10;
my $commandName="netcat";
my %connections=();


sub update_connection_list {
    my ($output,$error) = lsof("-i", "-P", "-n", "-a", "-s", "TCP:ESTABLISHED");
    say "update";

    while (my ($k, $v) = (each $output)) {
        for my $f (@{$v->{files}}) {
            my $con=$f->{'file name'};
            my $rcon= join '->', reverse split '->', $con;

            $connections{$con}=undef;
            next unless $v->{'command name'} eq $commandName;

            $connections{$con}={pid=>$k, command=>$commandName};
        }
    }
}

my $cv=AnyEvent->condvar;
my $pcap;
$pcap = AnyEvent::Pcap->new(
                            device         => "lo",
                            filter         => "tcp port 12345",
                            packet_handler => sub {
                                my $nPackets=$#_/2-1;

                                for (0..$nPackets) {
                                    my $header = shift;
                                    my $packet = shift;

                                    my $ip = $pcap->utils->extract_ip_packet($packet);
                                    my $tcp = $pcap->utils->extract_tcp_packet($packet);

                                    my $xmit = localtime( $header->{tv_sec} );
                                    print "$xmit TCP: $ip->{src_ip}:$tcp->{src_port}"
                                            . " -> $ip->{dest_ip}:$tcp->{dest_port} $header->{len}\n";

                                    my $in="$ip->{src_ip}:$tcp->{src_port}"."->$ip->{dest_ip}:$tcp->{dest_port}";
                                    my $out="$ip->{dest_ip}:$tcp->{dest_port}"."->$ip->{src_ip}:$tcp->{src_port}";

                                    update_connection_list unless
                                            exists $connections{$in} ||
                                                    exists $connections{$out};

                                    $connections{$in}->{out}+=$header->{len} if exists $connections{$in};
                                    $connections{$out}->{in}+=$header->{len} if exists $connections{$out};
                                }
                            }
                           );

my $clearingTimer=AnyEvent->timer (after    => 300,
                                   interval => 300,
                                   cb       => sub {
                                       # TODO: clear unwanted connections
                                       while (my ($k, $v)=(each %connections)) {
                                           delete $connections{$k} unless defined $v;
                                       }
                                   });

my $loggingTimer=AnyEvent->timer (after    => $interval,
                                  interval => $interval,
                                  cb       => sub {
                                      # TODO: write to log and zero counters
                                      while (my ($k, $v)=(each %connections)) {
                                          p $v;
                                          next unless exists $v->{command};
                                          next unless $v->{command} eq $commandName;
                                          say "$v->{pid}: $k read: ", $v->{in}, "b/s wrote: ", $v->{out}, "b/s ";
                                          $v->{in}=$v->{out}=0;
                                      }
                                  });

$pcap->run();
$cv->recv;

1;
__END__

=head1 NAME

Nethoglogger - Loggs bandwidth of each connection thath belongs to a process.

=head1 SYNOPSIS

  nethoglogger [-l log_path] [-i interval] command_name

=head1 DESCRIPTION

Loggs process' used bandwidth info of each connection to a file in JSON format.


=head1 SEE ALSO

man lsof
man pcap

=head1 AUTHOR

X4lldux, E<lt>x4lldux@(none)E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by X4lldux

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.16.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
