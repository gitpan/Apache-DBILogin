# $Id: DBILogin.pm,v 1.1 1997/07/07 02:31:31 jdg117 Exp jdg117 $
package Apache::DBILogin;
use strict;
use Apache();
use Apache::Constants qw(OK AUTH_REQUIRED);
use Apache::DBI;
use HTTPD::UserAdmin();
use vars qw($VERSION);

$VERSION = '1.1';
my(%Config) = (
    AuthDBIDB => "",
    AuthDBIDriver => "",
);

sub handler {
    my($r) = @_;
    my($key,$val);
    my $attr = {
        DBType => 'SQL',
    };
    while(($key,$val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^AuthDBI//; 
        $attr->{$key} = $val;
    }
    $attr->{DB} = delete $attr->{User} if #bleh, inconsistent
        $attr->{Driver} eq "mSQL";
    
    print STDERR $attr->{User},"foo\n";
    return check($r, $attr);
}
 
sub check {
    my($r, $attr) = @_;
    my($res, $sent_pwd);
 
    ($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $user = $r->connection->user;

    print STDERR $user,"\t",$sent_pwd,"\t",$attr->{DB},"\t",$attr->{Driver},"\n";

    my $drh = DBI->install_driver( $attr->{Driver} );
    my $dbh = $drh->connect($attr->{DB},$user,$sent_pwd);
    unless( defined $dbh ) {
        $r->log_reason("user $user: $DBI::errstr", $r->uri);
        $r->note_basic_auth_failure;
        return AUTH_REQUIRED;
    }
    $dbh->disconnect;
    $r->header_in('Modperl_Password',$sent_pwd);
    return OK;
}
1;
 
__END__

=head1 NAME

Apache::DBILogin - authenticates via a DBI connection

=head1 SYNOPSIS

See the access.conf file and the documentation for Apache::AuthenDBI

=head1 DESCRIPTION

=pod

<Directory /opt/www/root>

AuthName MyAuth

AuthType Basic

PerlHandler Apache::Registry::handler

PerlAuthenHandler Apache::DBILogin::handler

SetHandler perl-script
 
PerlSetVar AuthDBIDB SQLNetAlias

PerlSetVar AuthDBIDriver Oracle

Options Indexes FollowSymLinks ExecCGI

AllowOverride All
 
<Limit GET POST>

allow from all

require valid-user

satisfy all

</Limit>

</Directory>

=cut

=head1 AUTHOR

John Groenveld E<lt>groenvel@cse.psu.eduE<gt>

=cut
