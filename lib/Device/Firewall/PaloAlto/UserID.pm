package Device::Firewall::PaloAlto::UserID;

use strict;
use warnings;
use 5.010;

# VERSION
# PODNAME
# ABSTRACT: Palo Alto User-ID Operations

use Device::Firewall::PaloAlto::Errors qw(ERROR);

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($fw) = @_;

    return bless { fw => $fw }, $class;
}

=head2 add_ip_mapping

Adds a user to IP mapping.

    # Bind the IP to a user with a timeout of 10 minutes
    $fw->user_id->add_ip_mapping('192.0.2.1', 'localdomain\greg.foletta', 10);

    # If no timeout is specified, defaults to one hour
    $fw->user_id->add_ip_mapping('192.0.2.1', 'localdomain\greg.foletta');

=cut

sub add_ip_mapping {
    my $self = shift;
    my ($ip, $name, $timeout) = @_;
    $timeout //= 60;

    return ERROR('No IP or user specified') unless defined $ip and defined $name;

    my $xml = _userid_xml(ip => $ip, name => $name, timeout => $timeout);
    my $r = $self->_send_userid_cmd( $xml ); 

    return $r ? 1 : $r;
}


=head2 rm_ip_mapping

Removes an IP mapping. Returns true if the mapping is removed, or L<Class::Error> if there is an error.

If a mapping does not exist and a remove is attempted, true is still returned as it is not an error to remove an entry that doesn't exist.

    $fw->user_id->rm_ip_mapping('192.0.2.1', 'localdomain\greg.foletta');

=cut

sub rm_ip_mapping {
    my $self = shift;
    my ($ip, $name) = @_;

    return ERROR('No IP or user specified') unless defined $ip and defined $name;

    my $xml = _userid_xml(ip => $ip, name => $name, logout => 1);
    my $r = $self->_send_userid_cmd( $xml );
    
    return $r ? 1 : $r;
}



sub _send_userid_cmd {
    my $self = shift;
    my ($xml_content) = @_;

    $self->{fw}->_send_request(type => 'user-id', cmd => $xml_content);
}


sub _userid_xml {
    my %args = @_;

    $XML::LibXML::skipXMLDeclaration = 1;
    my $xml = XML::LibXML->load_xml(string => _user_id_xml_template());

    # Create the login / logout entry
    my $action_n = $xml->createElement($args{logout} ? 'logout' : 'login');
    
    # Create the login entry and set the user attributes;
    my $entry = $xml->createElement('entry');
    for my $attr(qw(name ip timeout)) {
        next unless defined $args{$attr};
        $entry->setAttribute( $attr, $args{$attr} );
    }

    # Access the login tag and append the entry.
    my ($payload_n) = $xml->findnodes('/uid-message/payload');
    $action_n->appendChild($entry);
    $payload_n->appendChild($action_n); 

    return $xml->toString;
}


sub _user_id_xml_template {
    return q{
<uid-message>
    <version>1.0</version>
    <type>update</type>
    <payload>
    </payload>
</uid-message>
    };
}
            
                        
1;
