package Device::Firewall::PaloAlto::Test::NATPolicy;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

use overload 'bool' => 'bool_overload';

# VERSION
# PODNAME
# ABSTRACT: A Palo Alto NAT policy test result

=encoding utf8

=head1 SYNOPSIS

    use Test::More;
    my $result = $fw->test->rulebase( ... );

    # Object returns true or false in boolean context depending on whether the
    # flow was allowed / denied through the firewall.
    ok( $result, "Flow allowed");

=head1 DESCRIPTION

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_response) = @_;

    return bless $api_response, $class;
}


1;

