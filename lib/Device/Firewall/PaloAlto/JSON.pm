package Device::Firewall::PaloAlto::JSON;

use strict;
use warnings;
use 5.010;

# We don't want all of the automatic imports
use JSON qw();

use Data::Structure::Util qw(unbless);
use Carp;


# VERSION
# PODNAME
# ABSTRACT: JSON parent class for Device::Firewall::PaloAlto modules.

=encoding utf8

=head1 SYNOPSIS

    use parent qw(Device::Firewall::PaloAlto::JSON);

=head1 DESCRIPTION

This module should be used as a parent to allow the module to output a JSON representation of the object.

=cut

=head2 to_json

    # Output the ARP table to STDOUT
    $fw->op->arp_table->to_json;

    # Output the interfaces to the file 'interfaces.json'
    $fw->op->interfaces->to_json('interfaces.json');

=cut

sub to_json {
    my ($self, $filename) = @_;
    my $output_fh;

    my $structure = $self->pre_json_transform();

    if (defined $filename and !ref $filename) {
        open($output_fh, '>:encoding(UTF-8)', $filename);
        carp "Could not open file '$filename' for writing" unless $output_fh;
    }

    $output_fh //= *STDOUT;

    my $json_text = JSON->new->pretty->encode($structure);

    print {$output_fh} $json_text;
}

=head2 pre_json_transform

A sub can chose to override this sub which gives it a chance to transform the data structures before it's output to JSON.

The returned data structure will be transformed directly to JSON.

If the sub isn't overridden, the default behaviour is to return an unblessed '$self'.

=cut

sub pre_json_transform {
    my $self = shift;
    return unbless($self);
}

1;

