use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::DBILogin',
   DISTNAME      => 'Apache-DBILogin',
   VERSION_FROM  => 'DBILogin.pm',
   PREREQ_PM => { DBI => '0',
                  mod_perl => '0'}
);
