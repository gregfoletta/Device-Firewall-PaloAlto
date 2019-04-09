package Device::Firewall::PaloAlto::Op::IPUserMaps;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

use Device::Firewall::PaloAlto::Op::IPUserMap;

use Device::Firewall::PaloAlto::Errors qw(ERROR);


# VERSION
# PODNAME
# ABSTRACT: Palo Alto IP to user mapping table.

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_response) = @_;

    # Create a copy of the entries if defined, otherwise an empty list
    my @userid_entries = defined $api_response->{result}{entry} ? @{$api_response->{result}{entry}} : ();

    # Create the objects
    my @userid_obj = map { Device::Firewall::PaloAlto::Op::IPUserMap->_new($_) } @userid_entries;

    # Map to the IP
    my %ip_map = map { $_->ip => $_ } @userid_obj;

    return bless \%ip_map, $class;
}

=head2 ip

Returns a L<Device::Firewall::PaloAlto::Op::IPUserMap> object with details about the IP to user mapping for a user.

If there is no mapping for the IP, returns a L<Class::Error> object.

=cut

sub ip {
    my $self = shift;
    my ($ip) = @_;
    
    return ($self->{$ip} or ERROR("No IP mapping for IP $ip"));
}

=head2 to_array

Returns an array of L<Device::Firewall::PaloAlto::Op::IPUserMap> objects representing the current IP to user mappings.

=cut

sub to_array { return values %{$_[0]} }

1;

