my @GOBAL_VAR = ();
my %SUPPORTED_VAR = ();

sub load_waf_var_code {
    open FILE, "< waf_var.lua" or die "cannot open waf_var.lua";
    while(<FILE>) {
        if (/function\s+M\.(get_([^ ()]+))/) {
            my ($func_name, $name) = ($1, $2);
            $SUPPORTED_VAR{uc($name)} = $func_name;
            #print uc($name), "\n";
        }
    }
    close FILE;
}

sub parse_var {
}

sub parse_op {
    my ($str) = @_;
    if ($str =~ /^(!?)@(\w+)\s+(.+)/) {
        return [$2, $3, $1];
    }
    if ($str =~/^([^@].*)/) {
        return ['rx', $1];
    }
}

sub parse_act {
    my ($str) = @_;
    my @list = split /,/, $str;
    my @a = map { [$1, $2] if /([^:]+)(?::(.+))?/ } @list;
    return \@a;
}

sub parse {
    my ($str) = @_;
    my @list_of_rules = ();
    while ($str=~ /^\s*SecRule\s+(\S+)\s+"((?:[^"\n]|\\\")+)"\s+(?:\\\n)?\s*"((?:[^"\n]|\\\")+)"/mg) {
        my %rule = ();
        my ($variables, $operator, $actions) = ($1, $2, $3);
        #print "VAR: $variables, OP: $operator, ACT: $actions\n";
        my $op = parse_op $operator;
        my $act = parse_act $actions;
        unless ($op) {
            print "parse op error:$operator in $&\n";
            exit(-1);
        }
        unless ($act) {
            print "parse act error:$actions\n";
            exit(-1);
        }
        $rule{var} = $variables;
        $rule{op} = $op;
        $rule{act} = $act;
        push @list_of_rules, \%rule;
    }
    return \@list_of_rules;
}

sub gen_setvar {
    my ($str) = @_;

    if ($str =~ /['\"]?([^'\"]+)/) {
        $str = $1;
    }
    if ($str =~ /([^=]+)=\+(\S+)/) {
        $str = "$1 = $1 + $2";
    }
    
    $str =~ s/%{([^{}]+)}/$1/;

    print "$str\n";
}

sub generate {
    open LOG, ">gen.log";
    my ($ref) = @_;
    @list_of_rules = @$ref;
    for my $rule (@list_of_rules) {
        my $op = $rule->{op}->[0];
        my $var = $rule->{var};
        my $op_var = $rule->{op}->[1];
        my $op_neg = $rule->{op}->[2];
        unless(exists $SUPPORTED_VAR{uc($var)}) {
            printf LOG "not suppport $var\n";
            next;
        }
        unless (exists $GLOBAL_VAR{$var} ) {
            my $func_name = $SUPPORTED_VAR{uc($var)};
            printf "local $var = waf_var.$func_name()\n";
            $GLOBAL_VAR{$var} = 1;
        }
        if ($op_neg) {
            print "MATCHED_VAR_NAME, MATCHED_VAR = !waf_$op($var, \"$op_var\")\n";
            print "if MATCHED_VAR_NAME then\n";
        }
        else {
            print "MATCHED_VAR_NAME, MATCHED_VAR = !waf_$op($var, \"$op_var\")\n";
            print "if MATCHED_VAR_NAME then\n";
        }
        for my $act (@{ $rule->{act} }) {
            my $act_op = $act->[0];
            my $act_var = $act->[1];
            if ($act_op eq "t") {
                if ($act_var ne "none") {
                    print "$act_var()\n";
                }
            }
            elsif ($act_op eq "tag" ) {
                #pass
            }
            elsif ($act_op eq "setvar") {
                gen_setvar($act_var);
            }
            else {
                print "waf_$act_op($act_var)\n";
            }
        }
        print "end\n";
    }
}

load_waf_var_code();
$/=undef;
$str = <>;
generate(parse($str))
