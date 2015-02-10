use warnings;
use Carp qw( croak );
open LOG, ">gen.log";

my @GOBAL_VAR = ();
my %SUPPORTED_VAR = ();
my %SUPPORTED_OP = (within=>1,
                    contains=>1,
                    containsWord=>1,
                    rx=>1,
                    beginsWith=>1,
                    endsWith=>1,
                    pm=>1
    );

my %COLLECTION_VAR = (
    ARGS => 1,
    ARGS_NAMES =>1,
    ARGS_GET=>1,
    ARGS_GET_NAMES=>1,
    ARGS_POST=>1,
    ARGS_POST_NAMES=>1,
    REQUEST_COOKIES=>1,
    REQUEST_COOKIES_NAMES=>1,
    REQUEST_HEADERS=>1,
    REQUEST_HEADERS_NAMES=>1,
    RESPONSE_HEADERS=>1,
    RESPONSE_HEADERS_NAMES=>1,
    );

sub is_var_supported {
    my ($var) = @_;
    return exists $SUPPORTED_VAR{uc($var)};
}

sub is_op_supported {
    my ($op) = @_;
    return exists $SUPPORTED_OP{$op};
}

sub is_var_hash {
    my ($var) = @_;
    return exists $COLLECTION_VAR{$var};
}

sub is_var_collection {
    my ($var) = @_;
    return exists $COLLECTION_VAR{$var};
}

sub localize_op {
    for my $op (keys %SUPPORTED_OP) {
        print "local waf_$op = waf_op.$op\n"
    }
    print "local matched\n";
}

sub load_waf_var_code {
    open FILE, "< lua/waf_var.lua" or die "cannot open waf_var.lua";
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

# 解释每一条rule 为 variables operator actions
#
sub parse {
    my ($str) = @_;
    $str =~ s/\\\n//mg;
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

my $var_count = 0;
sub get_lua_var_name {
    return "v_" . $var_count++;
}

# 获取modsecurity ARG
sub get_mod_lua_arg_name {
    my ($var) = @_;
    unless(exists $GLOBAL_VAR{$var}) {
        my $name = get_lua_var_name();
        my $func_name = $SUPPORTED_VAR{uc($var)};
        unless ($func_name) {
            croak "$var is not suppored\n";
        }
        printf "local $name = waf_var.$func_name()\n";
        $GLOBAL_VAR{$var} = $name;
    }
    return $GLOBAL_VAR{$var};
}

sub get_negtive_args {
    my ($negtive_args) = @_;
    my $arg_name;
    my %expresions = ();
    for my $var (keys %{ $negtive_args }) {
        my @names = @{ $negtive_args->{$var} };
        $expresions{$var} = join "|", map { $var . ":" . $_ } @names;
    }
    my @ok = ();
    for my $var (keys %expresions) {
        if (exists $GLOBAL_VAR{ $expresions{$var} }) {
            push @ok, $var;
        }
    }
    my @result;
    for my $var (@ok) {
        push @result, [$var, $GLOBAL_VAR{ $expresions{$var} }, 0,  $expresions{$var}];
        delete $negtive_args->{$var};
    }
    # 现在是没有之前没有处理过的negtive
    my %cloned = ();
    for my $var (keys %{ $negtive_args }) {
        unless(exists $cloned{$var}) {
            my $name = get_lua_var_name();
            my $hash_name = get_mod_lua_arg_name($var);
            print "local $name = copy('$hash_name')\n";
            $cloned{$var} = $name;
            my @names = $negtive_args->{$var};
            my $exp = join "|", map { $var . ":" . $_ } @names;
            push @result, [$var, $name, 0, $exp];
            $GLOBAL_VAR{ $exp } = $name;
        }
        my $name = $cloned{$var};
        for my $exp ( @{ $negtive_args->{$var} } ) {
            # 非正则表达式，如 !REQUEST_COOKIES:user_name
            if ($exp =~ /\/([^\/]+)\/$/) {
                print "remove_by_rx_key($name, '$1')\n";
            }
            else {
                print "remove_by_key($name, '$exp')\n";
            }
        }
    }
    return \@result;
}

sub get_single_args {
    my ($single_args) = @_;
    my @result = ();
    for my $var (keys %$single_args) {
        my @names = @{ $single_args->{$var} };
        for my $exp (@names) {
            my $long_name = $var . ":" . $exp;
            if (exists $GLOBAL_VAR{$long_name}) {
                push @result, [$var, $GLOBAL_VAR{$long_name}, 1];
                next;
            }
            unless(exists $GLOBAL_VAR{$var} ) {
                my $lua_hash = get_mod_lua_arg_name($var);
                my $var_name = get_lua_var_name();
                print "local $var_name = $lua_hash" . "['$exp']\n";
                $GLOBAL_VAR{$long_name} = $var_name;
            }
            push @result, [$long_name, $GLOBAL_VAR{$long_name}, 1, $long_name];
        }
    }
    return \@result;
}

sub get_regex_args {
    my ($regex_args) = @_;
    my @result = ();

    for my $var ( keys %$regex_args ) {
        my @names = @{ $regex_args->{$var} };
        for my $regex (@names) {
            my $exp = $var . ":" . $regex;
            unless ( exists $GLOBAL_VAR{$exp} ) {
                my $lua_table = get_mod_lua_arg_name($var);
                my $var_name = get_lua_var_name();
                print "local $var_name = filter_by_rx($lua_table, '$regex')\n";
                $GLOBAL_VAR{$exp} = $var_name;
            }
            push @result, [$var, $GLOBAL_VAR{$exp}, 0, $exp];
        }
    }
    return @result;
}


# 将参数表达式如REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES
# 转化成lua表达式
# 返回结果[ ['REQUEST_COOKIES', 'v_1', 0], ['REQUEST_COOKIES_NAMES', 'v_2', 0], ['ARGS_NAMES', 'v_3', 0] ]
# 其中 0 表示是collection， 1表示是单个值
sub generate_vars {
    my ($vars) = @_;
    if (exists $GLOBAL_VAR{$vars} ) {
        return $GLOBAL_VAR{$vars};
    }

    # 怎样处理 REQUEST_HEADERS:'/(Content-Length|Transfer-Encoding)/'?
    while ($vars =~ /(!?[A-Z_]+:'\/[^'\/]+\/')/g) {
        push @tmp, $1;
    }
    $vars =~ s/(!?[A-Z_]+:'\/[^'\/]+\/')//g;
    my @list = split /\|/, $vars;
    push @list, @tmp;

    my %collection_args = ();
    my %single_args = ();
    my %negtive_args = ();
    my %regex_args = ();

    for my $v (@list) {
        # skip empty string
        unless($v) {
            next;
        }
        #print $v , "\n";
        unless ($v =~ /^!?([A-Z_]+)/) {
            croak "$v is invalid\n";
        }
        unless(is_var_supported($1)) {
            printf LOG "not suppport var $1\n";
            next;
        }
        if ( $v =~ /^[A-Z_]+$/ ) {
            $collection_args{$v} = 1;
        }
        elsif ( $v =~ /^([A-Z_]+):\/([^\/]+)\/$/ ||
                $v =~ /^([A-Z_]+):'\/([^'\/]+)\/'$/ ) {
            push @{ $regex_args{$1} }, $2;
        }
        elsif ( $v =~ /^([A-Z_]+):(.+)/) {
            push @{ $single_args{$1} }, $2;
        }
        elsif ( $v =~ /^!([A-Z_]+):'([^']+)'/ ||
                $v =~ /^!([A-Z_]+):(.+)/) {
            push @{ $negtive_args{$1} }, $2;
        }
    }

    my $res = get_single_args(\%single_args);
    push @result, @$res;

    $res = get_regex_args(\%regex_args);
    push @result, @$res;

    for my $var (keys %collection_args) {
        # 如果变量不存在nagtive的,那么就将变量的名字放到结果中
        unless(exists $negtive_args{$var} || exists $negtive_rx_args{$var}) {
            push @result, [$var, get_mod_lua_arg_name($var), (is_var_collection($var)? 0: 1) ];
        }
    }
    my $res = get_negtive_args(\%negtive_args);
    push @result, @$res;

    # 保留对该参数列表转化结果
    $GLOBAL_VAR{$vars} = \@result;
    return \@result;
}

sub transact_vars {
    my ($list, $acts) = @_;
    my @result = ();
    for my $var_info (@$list) {
        my ($var_name, $var_val, $var_type, $var_exp) = @$var_info;
        my @transactions  = grep { my $act = $_;
                                   my $act_op = $act->[0];
                                   my $act_var = $act->[1];
                                   $act_op eq "t" && $act_var ne "none" } @$acts;

        my $act_exp = join ",", map { $_->[0] . ":" . $_->[1] } @transactions;
        my $long_name = "$var_exp trans_by $act_exp";
        unless ($GLOBAL_VAR{$long_name}) {
            my $exp;
            for my $act (@transactions) {
                my $act_op = $act->[0];
                my $act_var = $act->[1];
                unless ($exp) {
                    $exp = "$act_var()";
                }
                else {
                    $exp = "$act_var($exp)";
                }
            }
            my $lua_var = get_lua_var_name();
            print "local $lua_var = $exp\n";
            $GLOBAL_VAR{$long_name} = $lua_var;
        }
        push @result, [$var_name, $GLOBAL_VAR{$long_name}, $var_type];
    }
    return \@result;
}

sub generate {
    my ($ref) = @_;
    @list_of_rules = @$ref;
    for my $rule (@list_of_rules) {
        my $op = $rule->{op}->[0];
        my $var = $rule->{var};
        my $op_param = $rule->{op}->[1];
        my $op_is_negtive = $rule->{op}->[2];

        unless(is_op_supported($op)) {
            printf LOG "not suppport op $op (VAR: $var)\n";
            next;
        }

        my $list = generate_vars($var);
        $list = transact_vars($list);
        for my $var_info (@$list) {
            my ($var_name, $var_val, $var_type) = @$var_info;
            if ($var_type == 0) {
                print "matched = waf_${op}_hash($var_val, \"$op_param\")\n";
            }
            else {
                print "matched = waf_${op}($var_val, \"$op_param\")\n";
            }
            if ($op_is_negtive) {
                print "if not matched then\n";
            }
            else {
                print "if matched then\n";
            }

            for my $act (@{ $rule->{act} }) {
                my $act_op = $act->[0];
                my $act_var = $act->[1];
                if ($act_op eq "t" || $act_op eq "tag") {
                    # pass
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
}

load_waf_var_code();
$/=undef;
$str = <>;
localize_op();
generate(parse($str))
