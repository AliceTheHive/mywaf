package WafApi;
use Data::Dumper;
use Carp qw( croak );

sub new {
    my ($class, $filename, $reg) = @_;
    my %result = load_waf_api($filename, $reg);
    $filename =~ /([a-z_]+)\.lua/;
    my $module_name = $1;
    my $self = { table => \%result,
                 module_name => $module_name };

    bless $self, $class;
    return $self;
}

sub load_waf_api {
    my ($file, $reg) = @_;
    open FILE, "< $file" or die "cannot open $file";
    my %result;
    for (<FILE>) {
        if (/$reg/) {
            my ($func_name, $name) = ($1, $2);
            if($name eq '' || $func_name eq '') {
                next;
            }
            $result{ uc($name) } = [$func_name, $name];
        }
    }
    close FILE;
    return %result;    
}

sub is_supported {
    my ($self, $api) = @_;
    return exists $self->{table}->{uc($api)};
}

sub get_function_name {
    my ($self, $api) = @_;
    return $self->{table}->{uc($api)}->[0];
}

sub gen_code {
    my ($self) = @_;
    my $module = $self->{module_name};
    print "local $module = require '$module'\n";
    while (my ($key, $value) = each $self->{table}) {
        my ($func_name, $var_name) = @$value;
        print "local waf_$var_name = ", $self->{module_name}, ".$func_name\n"; 
    }
}

1;
