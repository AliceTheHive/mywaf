use strict;
use warnings;
use Data::Dumper;
use Carp qw( croak );
open LOG, ">gen.log";

my %GLOBAL_VAR = ();
my %GLOBAL_EXP = ();
my %CACHED_EXP = ();
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

sub append_list {
    my ($list1, $list2) = @_;
    if ($list2) {
        push @$list1, @$list2;
    }
}

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

sub set_exp {
    my ($exp, $result) = @_;
    $GLOBAL_EXP{$exp} = $result;
}

sub get_exp {
    my ($var) = @_;
    return $GLOBAL_EXP{$var};
}

sub set_cached_exp {
    my ($exp, $result) = @_;
    croak "null" unless $exp;
    $CACHED_EXP{$exp} = $result;
}

sub get_cached_exp {
    my ($var) = @_;
    croak "null" unless $var;
    return $CACHED_EXP{$var};
}

sub set_var {
    my ($var, $result) = @_;
    $GLOBAL_VAR{$var} = $result;
}

sub get_var {
    my ($var) = @_;
    return $GLOBAL_VAR{$var};
}

sub localize_op {
    for my $op (keys %SUPPORTED_OP) {
        print "local waf_$op = waf_op.$op\n"
    }
    print "local waf_block = waf_act.block\n";
    print "local waf_logdata = waf_act.logdata\n";
    print "local waf_msg = waf_act.msg\n";
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


######################## BEGINING OF PARSING ################################
my %ATTRIBUTE = ( id=>1, msg=>1 );

sub is_attribute {
    my ($str) = @_;
    return (exists $ATTRIBUTE{$str});
}

sub parse_var {
    my ($vars) = @_;
    # $vars = quotemeta $vars;
    if (get_cached_exp $vars) {
        return get_cached_exp $vars;
    }
    my $original_exp = $vars;
    my @tmp;
    # 怎样处理 REQUEST_HEADERS:'/(Content-Length|Transfer-Encoding)/'?
    while ($vars =~ /(!?[A-Z_]+:'\/[^'\/]+\/')/g) {
        push @tmp, $1;
    }
    $vars =~ s/(!?[A-Z_]+:'\/[^'\/]+\/')//g;
    my @list = split /\|/, $vars;
    push @list, @tmp;

    my @collection_args = ();
    my %single_args = ();
    my %negtive_args = ();
    my %regex_args = ();

    for my $v (@list) {
        # skip empty string
        unless($v) {
            next;
        }
        if ($v ~~ /^([A-Z_]+)/ and ! is_var_supported($1)) {
            next;
        }
        if ( $v =~ /^[A-Z_]+$/ ) {
            push @collection_args, $v;
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
    my %result = ( collection=> \@collection_args,
                   regex   => \%regex_args,
                   single  => \%single_args,
                   negtive => \%negtive_args,
                   original =>$original_exp);
    return \%result;
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

sub is_chain {
    my ($rule) = @_;
    for my $act (@{ $rule->{act} }) {
        return 1 if ($act->[0] eq "chain");
    }
    return 0;
}

# 解释每一条rule 为 variables operator actions
#
sub parse {
    my ($str) = @_;
    $str =~ s/\\\n//mg;
    my @lines = split /\n/, $str;

    my $previous_rule;
    my @list_of_rules = ();
    for my $line (@lines) {
        if ($line =~ /^\s*SecRule\s+(\S+)\s+"((?:[^"\n]|\\\")+)"\s+(?:\\\n)?\s*"((?:[^"\n]|\\\")+)"/) {
            my %rule = ();
            my ($variables, $operator, $actions) = ($1, $2, $3);
            #print "VAR: $variables, OP: $operator, ACT: $actions\n";
            my $vars = parse_var $variables;
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
            $rule{type} = 'SecRule';
            $rule{var} = $vars;
            $rule{op} = $op;
            $rule{act} = $act;

            map { $rule{$_->[0]} = $_->[1] } grep { is_attribute $_->[0] } @$act;

            my $ignore = 0;
            if ($previous_rule) {
                $previous_rule->{"chain"} = \%rule;
                $ignore = 1;
            }
            if (is_chain(\%rule)) {
                $previous_rule = \%rule;
            }
            else {
                $previous_rule = undef;
            }
            unless ( $ignore ) {
                push @list_of_rules, \%rule;
            }
        }
        elsif ($line =~ /^\s*SecMarker\s+(\S+)/) {
            my %rule = ();
            $rule{type} = 'SecMarker';
            $rule{var} = $1;
            push @list_of_rules, \%rule;
            $previous_rule = undef;
        }
    }
    return \@list_of_rules;
}

############################ END OF PARSING #################################

########################## BEGIN OF GENERATION ##############################
sub gen_setvar {
    my ($str, $act_param) = @_;
    # ignore this
    # tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/LDAP_INJECTION-%{matched_var_name}=%{tx.0}
    if ($str =~ /[^-]+-.*=.+/) {
        return;
    }

    if ($str =~ /['\"]?([^'\"]+)/) {
        $str = $1;
    }
    if ($str =~ /([^=]+)=\+(\S+)/) {
        $str = "$1 = $1 + $2";
    }
    $str = parse_act_var($str, $act_param);

    print "$str\n";
}

my $var_count = 0;
sub get_lua_var_name {
    return "v_" . $var_count++;
}

# 获取modsecurity ARG
sub get_main_arg {
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
        $expresions{$var} = join "|", map { "!$var:$_" } @names;
    }
    my @result = ();
    for my $var (keys %expresions) {
        if (get_exp $expresions{$var}) {
            push @result, get_exp $expresions{$var};
            delete $negtive_args->{$var};
        }
    }

    # 现在是没有之前没有处理过的negtive
    my %cloned = ();
    for my $var (keys %{ $negtive_args }) {
        unless(exists $cloned{$var}) {
            my $name = get_lua_var_name();
            my $hash_name = get_main_arg($var);
            print "local $name = copy('$hash_name')\n";
            $cloned{$var} = $name;
            my @names = @ {$negtive_args->{$var} };
            my $exp = join "|", map { "!$var:$_" } @names;
            push @result, [$var, $name, 0, $exp];
            set_exp $exp, [$var, $name, 0, $exp];
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
        for my $sub_var (@names) {
            my $exp = $var . ":" . $sub_var;
            unless(get_exp $exp) {
                my $lua_hash = get_main_arg($var);
                my $var_name = get_lua_var_name();
                print "local $var_name = $lua_hash" . "['$exp']\n";
                set_exp $exp, [$exp, $var_name, 1, $exp];
            }
            push @result, get_exp($exp);
        }
    }
    return \@result;
}

sub get_regex_args {
    my ($regex_args) = @_;
    my @result;

    for my $var ( keys %$regex_args ) {
        my @names = @{ $regex_args->{$var} };
        for my $regex (@names) {
            my $exp = $var . ":" . $regex;
            unless ( get_exp $exp ) {
                my $lua_table = get_main_arg($var);
                my $var_name = get_lua_var_name();
                print "local $var_name = filter_by_rx($lua_table, '$regex')\n";
                set_exp $exp, [$var, $var_name, 0, $exp];
            }
            push @result, get_exp($exp);
        }
    }
    return \@result;
}


# 将参数表达式如REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES
# 转化成lua表达式
# 返回结果[ ['REQUEST_COOKIES', 'v_1', 0, '!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/'],
#           ['REQUEST_COOKIES_NAMES', 'v_2', 0, 'REQUEST_COOKIES_NAMES'],
#           ['ARGS_NAMES', 'v_3', 0, 'ARGS_NAMES']  ]
# 其中 0 表示是collection， 1表示是单个值
sub generate_vars {
    my ($vars) = @_;
    if (get_cached_exp $vars->{original}) {
        return get_cached_exp $vars->{original};
    }
    my @tmp;
    my @result;
    my $res = get_single_args($vars->{single});
    #print "s:", Dumper($res);
    append_list(\@result, $res);

    $res = get_regex_args($vars->{regex});
    #print "r:", Dumper($res);
    append_list(\@result, $res);

    for my $var (@{ $vars->{collection} } ) {
        unless (get_exp $var) {
            set_exp $var, [$var, get_main_arg($var), (is_var_collection($var)? 0: 1), $var ];
        }
        # 如果变量不存在nagtive的,那么就将变量的名字放到结果中
        unless (exists $vars->{negtive}->{$var} ) {
            push @result, get_exp $var;
        }
    }
    $res = get_negtive_args($vars->{negtive});
    #print "n:", Dumper($res);
    append_list(\@result, $res);

    # 保留对该参数列表转化结果
    set_cached_exp $vars->{original}, \@result;
    return \@result;
}

sub combine_vars {
    my ($list) = @_;
    croak "list is null" unless $list;
    my $lua_table = get_lua_var_name();

    if (@$list == 1) {
        my $var_info = $list->[0];
        my ($var_name, $var_val, $var_type, $var_exp) = @$var_info;
        return ["combine $var_exp", $var_val]
    }
    my $exp = "combine " . join "|" , map { $_->[3] } @$list;
    if (get_cached_exp $exp) {
        return get_cached_exp $exp;
    }

    print "local $lua_table = {}\n";
    for my $var_info (@$list) {
        my ($var_name, $var_val, $var_type, $var_exp) = @$var_info;
        if ($var_type == 1) {
            my $lua_var = get_lua_var_name();
            print "local $lua_var = { $var_name=$var_val }\n";
            print "table.insert($lua_table, $lua_var)\n";
        }
        else {
            print "table.insert($lua_table, $var_val)\n";
        }
    }
    set_cached_exp $exp, [ $exp, $lua_table ];
    return [ $exp, $lua_table ];
}

# 使用transaction动作处理已经生成的变量
sub transform_vars {
    my ($combined_var, $acts) = @_;
    my ($combined_name, $combined_val) = @$combined_var;

    my @transactions  = grep { my $act = $_;
                               my $act_op = $act->[0];
                               my $act_var = $act->[1];
                               $act_op eq "t" && ($act_var ne "none" && $act_var ne "urlDecodeUni")} @$acts;
    # no need for transform
    if (@transactions == 0) {
        return $combined_val;
    }

    my $act_exp = join ",", map { $_->[0] . ":" . $_->[1] } @transactions;
    my $long_name = "$combined_name trans_by $act_exp";
    unless (get_exp $long_name) {
        my $exp;
        for my $act (@transactions) {
            my $act_op = $act->[0];
            my $act_var = $act->[1];
            unless ($exp) {
                $exp = "$act_var($combined_val)";
            }
            else {
                $exp = "$act_var($exp)";
            }
        }
        my $lua_var = get_lua_var_name();
        print "local $lua_var = $exp\n";
        set_exp $long_name, $lua_var;
    }
    return get_exp $long_name;
}

sub replace_var_inside {
    my ($expression, $var, $value, $tok) = @_;
    $var = quotemeta($var);
    if ($tok) {
        $expression =~ s/%{$var}/${tok} \.\. ${value} \.\. $tok/ig;
    } else {
        $expression =~ s/%{$var}/$value/ig;
    }
    return $expression;
}

sub parse_act_var {
    my ($statement, $hash) = @_;
    my $tok;
    if ($statement =~ /^('|")?.*('|")?$/) {
        $tok = $1;
    }
    my $matched_name = "mached_name";
    if ($hash && exists $hash->{'MATCHED_VAR_NAME'}) {
        $matched_name = $hash->{'MATCHED_VAR_NAME'};
        $statement =~ s/%{MATCHED_VAR_NAME}/$matched_name/ig;
        delete $hash->{'MATCHED_VAR_NAME'};
    } else {
        $statement = replace_var_inside($statement, "MATCHED_VAR_NAME", ${matched_name}, $tok);
    }
    $statement = replace_var_inside($statement, "MATCHED_VAR", "matched[0]", $tok);

    $hash->{"TX.0"} = 'matched[0]';
    for my $key (keys %$hash) {
        my $val = $hash->{$key};
        $statement = replace_var_inside($statement, $key, $val, $tok);
    }

    # replace %{tx.score} to waf_var_tx.score
    $statement =~ s/%{(tx\.\w+)}/$1/ig;

    if ($statement =~ /(%{[^}]+})/) {
        croak "unknown variable $1 :", Dumper($hash);
    }
    # replace tx.score to tx['score']
    $statement =~ s/tx\.(\w+)/waf_var_tx\['$1'\]/ig;

    return $statement;
}

sub get_act_param {
    my ($rule) = @_;
    my %result;

    $result{'rule.id'} = $rule->{id};
    $result{'rule.msg'} = $rule->{msg};
    return \%result;
}

sub generate_acts {
    my ($acts, $act_param) = @_;
    my %ignore = ( t      => 1,
                   tag    => 1,
                   capture=> 1,
                   rev    => 1,
                   ver    => 1,
                   maturity=>1,
                   ctl    => 1,
                   chain  => 1,
                   accuracy=>1);
    for my $act (@$acts) {
        my $act_op = $act->[0];
        my $act_var = $act->[1];
        if (exists $ignore{$act_op}) {
            # ingore t:xxx or tag:xxx
            # because t:xxx have been done by transform_vars()
        }
        elsif ($act_op eq "setvar") {
            gen_setvar($act_var, $act_param);
        }
        elsif ($act_op eq "skipAfter") {
            print "goto $act_var\n";
        }
        else {
            unless($act_var) {
                print "waf_$act_op()\n";
            }
            else {
                $act_var = parse_act_var($act_var, $act_param);
                print "waf_$act_op($act_var)\n";
            }
        }
    }
}

my %DISRUPTIVE = (
    allow => 1,
    deny => 1,
    block => 1
    );
sub is_act_disruptive {
    my ($act) = @_;
    return (exists $DISRUPTIVE{$act});
}


sub find_act {
    my ($name, $acts) = @_;
    for my $a (@$acts) {
        if ($a->[0] eq $name) {
            return $a;
        }
    }
}

#
# When dealing with chained rules, non-disruptive actions are executed as
# soon as the rule matches. The ctl action is considered a
# non-disruptive action (examples of disruptive actions are: allow, deny.
# block etc.).
#
sub generate {
    my ($ref) = @_;
    my @list_of_rules = @$ref;

    for my $rule (@list_of_rules) {
        my $op = $rule->{op}->[0];
        my $var = $rule->{var};
        my $op_param = $rule->{op}->[1];
        my $op_is_negtive = $rule->{op}->[2];

        if ($rule->{type} eq 'SecMarker') {
            my $marker = $rule->{var};
            print "::${marker}::\n";
            next;
        }
        unless (is_op_supported($op)) {
            printf LOG "not suppport op $op (VAR: $var)\n";
            next;
        }
        my $list = generate_vars($var);
        next unless $list;
        my $combined_var = combine_vars($list);
        my $lua_var = transform_vars($combined_var, $rule->{act});

        print "matched, matched_name = waf_${op}_hash_list($lua_var, \"$op_param\")\n";
        my @disruptive = grep { is_act_disruptive $_->[0] } @{ $rule->{act} };
        my @non_disruptive = grep { !is_act_disruptive $_->[0] } @{ $rule->{act} };
        if ($op_is_negtive) {
            print "if not matched then\n";
        }
        else {
            print "if matched then\n";
        }
        my $res = get_act_param($rule);
        if ($rule->{chain}) {
            generate_acts \@non_disruptive, $res;
            my $chained_rule = $rule->{chain};
            $chained_rule->{id} = $rule->{id} unless $chained_rule->{id};
            $chained_rule->{msg} = $rule->{msg} unless $chained_rule->{msg};
            # todo 变量在嵌套if中变成局部可见了
            generate([ $rule->{chain} ]);
            generate_acts \@disruptive, $res;
        }
        else {
            generate_acts $rule->{act}, $res;
        }
        print "end\n";
    }
}

load_waf_var_code();
$/=undef;
my $str = <>;
localize_op();
my $result = parse($str);
#print Dumper($result);
generate($result);
