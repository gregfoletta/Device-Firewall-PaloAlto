package Device::Firewall::PaloAlto::Op::HA;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

# VERSION
# PODNAME
# ABSTRACT: Palo Alto high availability information.

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut


sub _new {
    my $class = shift;
    my ($api_response) = @_;
    my %ha;

    $ha{enabled} = $api_response->{result}{enabled} eq 'yes' ? 1 : 0;
    $ha{local} = $api_response->{result}{group}{'local-info'};
    $ha{remote} = $api_response->{result}{group}{'peer-info'};

    # There's a lot of information which, at this stage, I don't think is important. 
    # This module is interested in the current state of the HA, not configuration 
    # items. The following is a list of keys we remove from the local and remote 
    # structures
    my @removed_keys = qw(
        av-version vpnclient-version gpclient-version gpclient-version threat-version
        url-version app-version vm-license active-passive 
        platform-model build-rel
    );

    delete @{$ha{local}}{ @removed_keys };
    delete @{$ha{remote}}{ @removed_keys };

    bless \%ha, $class;
} 

=head2 enabled

Returns true if HA is enabled on the firewall, otherwise returns false

=cut

sub enabled { return $_[0]->{enabled} ? 1 : () }

=head2 state

Returns a list containing both the local and remote states of the firewalls. States can be:

=over 4

=item initial 

=item active

=item passive

=item active-primary

=item active-secondary

=item tentative

=item non-functional

=item suspended

=item unknown

=back


    my ($local_state, remote_state) = $fw->ha->state;

Returns false if HA is not enabled on the firewall.

=cut

sub state {
    my $self = shift;

    return unless $self->{enabled};

    return (
        $self->{local}{state},
        $self->{remote}{state}
    );
}



=head2 connection_status

Returns true if the firewall has a HA connection to its peer, otherwise if there is no connection or HA is not enabled, returns false.

=cut

sub connection_status { 
    my $self = shift;
    return ($self->{enabled} and $self->{remote}{'conn-status'} eq 'up') ? 1 : "";
}



=head2 compatibility 

Returns a list the compatibility state between the HA pairs.

    my %compat_state = $fw->op->ha->compatibility;

The hash is structured as follows:

    {
        app         => '',
        av          => '',
        build       => '',
        gpclient    => '',
        threat      => '',
        url         => '',
        vpnclient   => ''
    }

If HA is not enabled on the firewall, returns an empty list.
    
=cut

sub compatibility {
    my $self = shift;

    return unless $self->{enabled};

    my @compatibility_keys = qw(
        vpnclient-compat 
        threat-compat 
        app-compat 
        av-compat
        build-compat 
        gpclient-compat 
        url-compat
    );

    my %compatibility = map { my $key = $_; $key =~ s{-compat}{}; $key => $self->{local}{$_} } @compatibility_keys;

    return %compatibility;
}



1;

