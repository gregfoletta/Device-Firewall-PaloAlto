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
    my $result = $fw->test->natpolicy( ... );

    # Object returns true or false in boolean context depending on whether the
    # flow hit a NAT policy or not.
    ok( $result, "Flow allowed");

=head1 DESCRIPTION

This class represents the return value from a NAT policy test.

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_response) = @_;

    return $api_response unless $api_response;

    my %result = %{ $api_response->{result}{rules} };

    if (%result) {
        %result = (
            name => $result{entry}[0],
            policy_hit => 1,
        );
    } else {
        %result = (
            name => '',
            policy_hit => 0,
        );
    }

    return bless \%result, $class;
}


=head2 rulename

Returns the name of the rule the flow hit in the NAT rulebase. If the flow hit not rule, an empty string is returned.

=cut

sub rulename { return $_[0]->{name} }


sub bool_overload { return $_[0]->{policy_hit} }

1;

