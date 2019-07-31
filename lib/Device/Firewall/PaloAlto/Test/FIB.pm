package Device::Firewall::PaloAlto::Test::FIB;

use strict;
use warnings;
use 5.010;

# VERSION
# PODNAME
# ABSTRACT: Representation of a Palo Alto FIB object.

use parent qw(Device::Firewall::PaloAlto::JSON);

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_response) = @_;
    my %obj;

    # Return the error
    return $api_response unless $api_response;

    # Is there an entry?
    $obj{fib_entry} = defined $api_response->{result}{nh};

    # Are there ECMP routes?
    $obj{ecmp} = 0;
    my @ecmp_fib_entries;
    if ($api_response->{result}{mpath}) {
        $obj{ecmp} = 1;
        # Extract out the entries we want into hashrefs
        @ecmp_fib_entries = 
            map { { %{ $_ }{qw(ip nh interface metric)} } }
            @{ $api_response->{result}{mpath}{entry} };
    }

    # Concatenate the ECMP entries together
    $obj{entries} = [
        { %{ $api_response->{result} }{qw(ip nh interface metric)} },
        @ecmp_fib_entries
    ];

    return bless \%obj, $class;
}


1;

