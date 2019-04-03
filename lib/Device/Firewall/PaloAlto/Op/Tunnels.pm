package Device::Firewall::PaloAlto::Op::Tunnels;

use strict;
use warnings;
use 5.010;

use Device::Firewall::PaloAlto::Op::Tunnel;

use parent qw(Device::Firewall::PaloAlto::JSON);

# VERSION
# PODNAME
# ABSTRACT: Palo Alto IPSEC security associations

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

This object represents IPSEC tunnels on the firewall.

=cut

sub _new {
    my $class = shift;
    my ($ike_sas, $ipsec_sas) = @_;
    my %tunnels;

    # Iterate through the phase 1 and key them by the name of the gateway.
    $tunnels{$_->{name}}{phase_1} = $_ foreach @{$ike_sas->{result}{entry}};
    $tunnels{$_->{gateway}}{phase_2} = $_ foreach @{$ipsec_sas->{result}{entries}{entry}};

    # API CRUFT: there whitespace following the remote IP.
    $_->{phase_2}{remote} =~ s{\s+$}{} foreach values %tunnels;
    

    # Map the values to tunnel objects, still keyed on the IKE gateway name.
    %tunnels = map { $_ => Device::Firewall::PaloAlto::Op::Tunnel->_new($tunnels{$_}) } keys %tunnels;

    return bless \%tunnels, $class;
}


=head2 gw

Returns a L<Device::Firewall::PaloAlto::Op::Tunnel> object that is assoicated with the name of the IKE gateway.

    my $p2p = $fw->op->tunnels->gw('remote_site');

=cut

sub gw {
    my $self = shift;
    my ($gw) = @_;
    return $self->{$gw}
};



=head2 to_array

Returns an array of L<Device::Firewall::PaloAlto::Op::Tunnel> objects, one for each IPSEC tunnel.

=cut

sub to_array { return values %{$_[0]} }

1;

