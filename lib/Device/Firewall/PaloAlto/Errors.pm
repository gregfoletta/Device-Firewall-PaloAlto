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
    croak $errstring if (caller())[1] eq '-e';

    return Class::Error->new($errstring, $errno);
}

1;

