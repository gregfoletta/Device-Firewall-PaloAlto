package Device::Firewall::PaloAlto::Op::Interface;

use strict;
use warnings;
use 5.010;

# VERSION
# PODNAME
# ABSTRACT: Palo Alto firewall interface

use parent qw(Device::Firewall::PaloAlto::JSON);

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_return) = @_;

    return $api_return unless $api_return;

    return bless $api_return, $class;
}


=head2 name

Returns the name of the interface.

=head2 state

State of the interface. Returns the either 'up' or 'down' depending on the interface state.

=head2 ip

Returns the IPv4 address and CIDR of the interface (e.g '192.0.2.0/24') or the empty string if there is no IPv4 address assigned to the interfaces.

=head2 vsys

Returns the vsys ID (1, 2, etc) of the vsys the interface is a member of.

=cut

=head2 zone

Returns the name of the zone the interface is in.
If the interface is not a member of a zone, returns an empty string.

=cut

sub name { return $_[0]->{name} }

sub state { return $_[0]->{state} }

sub ip { return $_[0]->{ip} }

sub vsys { return $_[0]->{vsys} }

sub zone { 
    my $self = shift;
    return ref $self->{zone} eq 'HASH'
        ? ''
        : $self->{zone}
}

1;

