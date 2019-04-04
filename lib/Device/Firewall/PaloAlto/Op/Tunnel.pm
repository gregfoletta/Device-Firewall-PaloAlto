package Device::Firewall::PaloAlto::Op::Tunnel;

use strict;
use warnings;
use 5.010;

use DateTime::Format::Strptime;

use parent qw(Device::Firewall::PaloAlto::JSON);

# VERSION
# PODNAME
# ABSTRACT: Palo Alto IPSEC tunnel

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

This object represents an IPSEC tunnel, including both phase 1 (IKE / IKEv2) and phase 2 parameters.

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($tunnel_r) = @_;
    my %tunnel = %{$tunnel_r};

    # P1 params are in one string split by forward slashes as well
    # as some spaces. We split these out and clean up the spaces.
    # We don't use the in-place modifier so we can remain compatble with
    # verions prior to 5.1.4.
    # https://www.perl.com/pub/2011/05/new-features-of-perl-514-non-destructive-substitution.html/
    $tunnel{phase_1}{params} = [ 
        map { my $c = $_; $c =~ s{ }{}; $c }
        split('/', delete $tunnel{phase_1}{algo}) 
    ];

    # Unify the P2 params into a single array.
    $tunnel{phase_2}{params} = [
        delete $tunnel{phase_2}{proto},
        delete $tunnel{phase_2}{enc},
        delete $tunnel{phase_2}{hash},
    ];

    #Input and output SPIs are moved into an array
    $tunnel{phase_2}{spis} = [
        delete $tunnel{phase_2}{i_spi},
        delete $tunnel{phase_2}{o_spi},
    ];

    return bless \%tunnel, $class;
}


sub _dt_parser {
    return DateTime::Format::Strptime->new(
        pattern => '%b.%d %T'
    );
}


=head2 p1_params

Returns a list of the parameters negotiated in phase 1. The parameters are authentication method, Diffie-Helman group, encryption algorithm, and hash algorithm.

    my ($auth, $dh_grp, $enc, $hash) = $fw->op->tunnels->gw('remote_site')->p1_params();

=cut

sub p1_params { return @{$_[0]->{phase_1}{params}} }


=head2 p2_params

Returns a list of the parameters negotiated in phase 1. The parameters are transport, encryption algorithm, and hash algorithm.

    my ($transport, $enc, $hash) = $fw->op->tunnels->gw('remote_site')->p2_params();

=cut

sub p2_params { return @{$_[0]->{phase_2}{params}} }

=head2 remote_ip

The remote IP address of the peer.

=cut

sub remote_ip { return $_[0]->{phase_2}{remote} }

=head2 gateway

The name of the IKE gateway used by this tunnel.

=cut

sub gateway { return $_[0]->{phase_1}{name} }

=head2 spis

Returns a list containing the input and output SPIs for phase 2. The first element is the input SPI, and the second element is the output SPI.

    my ($input_spi, $output_spi) = $fw->op->tunnels->gw('remote_site')->spis();

=cut

sub spis { return @{$_[0]->{phase_2}{spis}} }

1;

