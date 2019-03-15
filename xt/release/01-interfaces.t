use Test::More; 
use List::MoreUtils qw(pairwise);
use Device::Firewall::PaloAlto;

my $firewall_ip = $ENV{PA_FW_IP} or BAIL_OUT "'PA_FW_IP' environment variable not set. Set this to the IP/hostname of the firewall to test against.";

my $fw = Device::Firewall::PaloAlto->new(uri => "http://$firewall_ip")->auth;
my @interfaces = $fw->op->interfaces->to_array;

my $interface_regex = qr{^(
    ethernet\d+/\d+(\.\d+)? |
    vlan(\.\d+)? |
    loopback(\.\d+)? |
    tunnel(\.\d+)?
$)}xms;

for my $interface (@interfaces) {
    my $name = $interface->name;
    # Does the interface name make sense
    ok( $name =~ $interface_regex, "($name) name" );

    # Is the interface state either down or up
    ok( $interface->state =~ m{^down|up$}xms, "($name) state" );

    # IPv4 address should either be a proper IPv4 or an empty string
    like( $interface->ip, qr{\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}|^$}xms, "($name) IP Address" );

    like( $interface->vsys, qr{\d+}, "($name) vsys ID" );

}




done_testing();
