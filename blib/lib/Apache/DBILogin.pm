# $Id: DBILogin.pm,v 1.3 1997/10/16 18:39:54 jdg117 Exp $
package Apache::DBILogin;
use strict;
use Apache();
use Apache::Constants qw(OK SERVER_ERROR AUTH_REQUIRED);
use DBI;
use HTTPD::UserAdmin();
use vars qw($VERSION);

$VERSION = '1.3';
my(%Config) = (
    'Auth_DBI_data_source' => '',
);
my $prefix = "Apache::DBILogin";

sub handler {
    my($r) = @_;
    my($key,$val);
    my $attr = {
        DBType => 'SQL',
    };
    while(($key,$val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^Auth_DBI_//;
        $attr->{$key} = $val;
    }
    
    return check($r, $attr);
}
 
sub check {
    my($r, $attr) = @_;
    my($res, $sent_pwd);
 
    ($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $user = $r->connection->user;

    unless ( $attr->{data_source} ) {
        $r->log_reason("$prefix is missing the source parameter for database connect", $r->uri);
        return SERVER_ERROR;
    }

    my $dbh = DBI->connect($attr->{data_source},$user,$sent_pwd);
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

 #in access.conf
 <Directory /opt/www/root>
 AuthName MyAuth
 AuthType Basic
 PerlHandler Apache::Registry::handler
 PerlAuthenHandler Apache::DBILogin::handler
 SetHandler perl-script
 
 PerlSetVar Auth_DBI_data_source dbi:Oracle:SQLNetAlias
 
 Options Indexes FollowSymLinks ExecCGI
 AllowOverride All
  
 <Limit GET POST>
 allow from all
 require valid-user
 satisfy all
 </Limit>
 </Directory>

=head1 ENVIRONMENT

Applications may access the clear text password via the environment
variable B<HTTP_MODPERL_PASSWORD>

=head1 SEE ALSO

mod_perl(1), Apache::DBI(3), and Apache::AuthenDBI(3)

=head1 AUTHOR

John Groenveld E<lt>groenveld@acm.orgE<gt>

=cut
