package Nethoglogger;

use v5.10.1;
use strict;
use warnings;

use AnyEvent;
use AnyEvent::Pcap;
use Unix::Lsof;
use JSON;

our $VERSION = '0.01';



1;
__END__

=head1 NAME

Nethoglogger - Loggs bandwidth of each connection thath belongs to a process.

=head1 SYNOPSIS

  nethoglogger [-c process_name] [-l log_path] [-i interval]

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
