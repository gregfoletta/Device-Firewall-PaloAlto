package Local::TestSupport;

use strict;
use warnings;
use 5.010;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(pseudo_api_call);

use Device::Firewall::PaloAlto::API;

# VERSION
# PODNAME
# ABSTRACT: Test support functions

=encoding utf8


=head1 DESCRIPTION

Support functions to test the Device::Firewall::PaloAlto module.

=head1 METHODS

=head2 pseudo_api_call

Takes a file path and a sub ref and returns an object as if an API call had been made to the firewall.
    
=cut

sub pseudo_api_call {
    my ($xml_file, $obj_constructor) = @_;

    open(my $fh, '<:encoding(UTF8)', $xml_file) or return;
    my $xml = do { local $/ = undef, <$fh> };
    my $api = Device::Firewall::PaloAlto::API::_check_api_response($xml);
    return $obj_constructor->($api);; 
}

1;

