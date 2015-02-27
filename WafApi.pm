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
            $result{ uc($name) } = $func_name    
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
    return $self->{table}->{uc($api)};
}

sub gen_code {
    my ($self) = @_;
    while (my ($key, $value) = each $self->{table}) {
        print "local waf_", lc($key), " = ", $self->{module_name}, ".$value\n"; 
    }
}

1;
