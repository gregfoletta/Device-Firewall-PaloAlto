package Device::Firewall::PaloAlto::Op::InterfaceStats;

use strict;
use warnings;
use 5.010;

# VERSION
# PODNAME
# ABSTRACT: Palo Alto firewall interface statistics.

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

    # Return the Class::Error object
    return $api_return if !$api_return;

    return bless $api_return, $class;
}


=head2 hw_bytes

    my ($bytes_in, $bytes_out) = $fw->op->interface_stats('ethernet1/1')->hw_bytes;

Returns the number of bytes received and sent on the interface.

=cut

sub bytes {
    my $self = shift;

    my $ifcounters = $self->{result}{ifnet}{counters}{ifnet}{entry}[0];

    return unless ref $ifcounters eq 'HASH';

    return @{$ifcounters}{qw(ibytes obytes)};
}


1;

