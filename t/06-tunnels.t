use strict;
use warnings;
use 5.010;

use Test::More tests => 5;
use Device::Firewall::PaloAlto::API;
use Device::Firewall::PaloAlto::Op::Tunnels;

open(my $ike, '<:encoding(UTF8)', './t/xml/06-tunnels_ike.t.xml') or BAIL_OUT('Could not open IKE XML file');
open(my $ipsec, '<:encoding(UTF8)', './t/xml/06-tunnels_ipsec.t.xml') or BAIL_OUT('Could not open IPSEC XML file');

ok( $ike, 'IKE XML file' ); 
ok( $ipsec, 'IPSEC XML file' ); 
my $xml_ike = do { local $/ = undef, <$ike> };
my $xml_ipsec = do { local $/ = undef, <$ipsec> };
ok( $xml_ike, 'IKE XML response' );
ok( $xml_ipsec, 'IPSEC XML response' );

my $api_ike = Device::Firewall::PaloAlto::API::_check_api_response($xml_ike);
my $api_ipsec  = Device::Firewall::PaloAlto::API::_check_api_response($xml_ipsec);

my $tun = Device::Firewall::PaloAlto::Op::Tunnels->_new($api_ike, $api_ipsec);

isa_ok( $tun, 'Device::Firewall::PaloAlto::Op::Tunnels' );
