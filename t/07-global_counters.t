use strict;
use warnings;
use 5.010;

use Test::More tests => 5;
use Device::Firewall::PaloAlto::API;
use Device::Firewall::PaloAlto::Op::VirtualRouter;

open(my $fh, '<:encoding(UTF8)', './t/xml/04-virtual_router.t.xml') or BAIL_OUT('Could not open XML file');

ok( $fh, 'XML file' ); 
my $xml = do { local $/ = undef, <$fh> };
ok( $xml, 'XML response' );

my $api = Device::Firewall::PaloAlto::API::_check_api_response($xml);

my $vr= Device::Firewall::PaloAlto::Op::VirtualRouter->_new($api);

isa_ok( $vr, 'Device::Firewall::PaloAlto::Op::VirtualRouter' );

my $route = $vr->route('0.0.0.0/0');
ok( $route, 'Route entry' );
isa_ok( $route, 'Device::Firewall::PaloAlto::Op::Route' );
