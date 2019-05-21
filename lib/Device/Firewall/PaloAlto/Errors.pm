package Device::Firewall::PaloAlto::Errors;

use strict;
use warnings;
use 5.010;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(ERROR);

use Class::Error;
use Carp;

# VERSION
# PODNAME
# ABSTRACT: Parent class for errors.

=encoding utf8

=head1 SYNOPSIS


=head1 DESCRIPTION

This is a parent class containing functions relating to errors.

=cut


sub ERROR {
    my ($errstring, $errno) = @_;

    $errno //= 0;

    # Are we in a one liner? If so, we croak out straight away
    croak $errstring if in_one_liner();

    return Class::Error->new($errstring, $errno);
}


sub in_one_liner {
    my $level = 0;
    my $filename;
    my @call_info;

    while (@call_info = caller($level++)) { $filename = $call_info[1] };
    return $filename eq '-e' ? 1 : 0;
}

1;

