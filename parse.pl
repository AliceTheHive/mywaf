use strict;
use warnings;
use Data::Dumper;
use Carp qw( croak );
open LOG, ">gen.log";

our %GLOBAL_VAR = ();
our %GLOBAL_EXP = ();
our %CACHED_EXP = ();
my $in_recurrence = 0;
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

use WafApi;
my $waf_var = new WafApi("lua/waf_var.lua", qr/function\s+M\.(get_([^ ()]+))/);
my $waf_trans = new WafApi("lua/waf_trans.lua", qr/function\s+M\.(([^ ()]+))/);
my $waf_op = new WafApi("lua/waf_op.lua", qr/function\s+M\.(([^ ()]+))/);
my $waf_act = new WafApi("lua/waf_act.lua", qr/function\s+M\.(([^ ()]+))/);
######################## BEGINING OF PARSING ################################
my %ATTRIBUTE = ( id=>1, msg=>1, phase=>1,maturity=>1, accuracy=>1, severity=>1);

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
    # deal with REQUEST_HEADERS:'/(Content-Length|Transfer-Encoding)/'?
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
        if ($v ~~ /^([A-Z_]+)/ && ! $waf_var->is_supported($1) && $1 !~ /TX/i) {
            print LOG "var:($v) is not supported\n";
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

use constant {
    ACT_HAVE_STR_VAR => 1,
    ACT_HAVE_VAR => 2,
    ACT_HAVE_NO_VAR => 3
};

sub act_token {
    my $target = shift;
    return sub {
      TOKEN: {
          return [$1, $2, ACT_HAVE_STR_VAR] if $target =~ /\G(\w+):'([^']+)'/gcx;
          return [$1, $2, ACT_HAVE_VAR] if $target =~ /\G(\w+):([^,]+)/gcx;
          return [$1, undef, ACT_HAVE_NO_VAR] if $target =~ /\G(\w+)/gcx;
          redo TOKEN if $target =~ /\G,/gcx;
          return;
        }
    };
}

# "phase:2,capture,t:none,t:urlDecodeUni,block,msg:'Detects MySQL comments, conditions and ch(a)r injections',id:'981240'"
sub parse_act {
    my ($str) = @_;
    my @result;
    my $get_token = act_token($str);
    my $tok;

    while ($tok = $get_token->()) {
        push @result, $tok;
    }

    return \@result;
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

my $var_count = 0;
sub get_lua_var_name {
    return "v_" . $var_count++;
}

# 获取modsecurity ARG
sub get_main_arg {
    my ($var) = @_;
    unless(exists $GLOBAL_VAR{$var}) {
        my $name;
        if ($var =~ /TX/) {
            $name = "waf_v";
        }
        else {
            $name = get_lua_var_name();
            my $func_name = $waf_var->get_function_name($var);
            unless ($func_name) {
                croak "$var is not suppored\n";
            }
            print "local $name = waf_var.$func_name()\n";
        }
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
            print "local $name = waf_var.copy($hash_name)\n";
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
                print "waf_var.remove_by_rx_key($name, '$1')\n";
            }
            else {
                print "waf_var.remove_by_key($name, '$exp')\n";
            }
        }
    }
    return \@result;
}

sub get_single_args {
    my ($single_args, $no_prefix) = @_;
    my @result = ();
    for my $var (keys %$single_args) {
        my @names = @{ $single_args->{$var} };
        for my $sub_var (@names) {
            my $exp = ($no_prefix)? $sub_var : ($var . ":" . $sub_var);
            unless(get_exp $exp) {
                my $lua_hash = get_main_arg($var);
                if ($var eq 'TX') {
                    # convert TX:0 TX:1 to matched['0'] matched['1']
                    if ($exp =~ /(\d+)$/) {
                        set_exp $exp, [$exp, "waf_v_tx\['$1'\]", 1, $exp];
                    }
                    # TX:PM_SCORE ==> waf_v['TX:PM_SCORE']
                    else {
                        set_exp $exp, [$exp, "$lua_hash\['$exp'\]", 1, $exp];
                    }
                }
                else {
                    my $var_name = get_lua_var_name();
                    print "local $var_name = $lua_hash" . "['$exp']\n";
                    set_exp $exp, [$exp, $var_name, 1, $exp];
                }
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
                print "local $var_name = waf_var.filter_by_rx_key($lua_table, '$regex')\n";
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

# 将一条规则的多个变量整合为一个变量
sub combine_vars {
    my ($list, $not_combine) = @_;
    croak "list is null" unless $list;
    my $lua_table = get_lua_var_name();

    if ($not_combine) {
        my $var_info = $list->[0];
        my ($var_name, $var_val, $var_type, $var_exp) = @$var_info;
        return ["combine $var_exp", $var_val]
    }

    my $exp = "combine " . join "|" , map { $_->[3] } @$list;
    if (get_cached_exp $exp) {
        return get_cached_exp $exp;
    }
    my $not_cache = 0;
    print "local $lua_table = {}\n";
    for my $var_info (@$list) {
        my ($var_name, $var_val, $var_type, $var_exp) = @$var_info;
        # 不能缓存对于单个规则有效的变量。例如tx:1等
        if ($var_name =~ /TX:/i) {
            $not_cache = 1;
        }
        # if var is single, convert it to a hash
        if ($var_type == 1) {
            my $lua_var = get_lua_var_name();
            print "local $lua_var = { ['$var_name']=$var_val }\n";
            print "table.insert($lua_table, $lua_var)\n";
        }
        else {
            print "table.insert($lua_table, $var_val)\n";
        }
    }
    if (! $not_cache) {
        set_cached_exp $exp, [ $exp, $lua_table ];
    }
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
            unless ($waf_trans->is_supported($act_var)) {
                print LOG "transform:$act_var is not supported\n";
                next;
            }
            my $func_name = $waf_trans->get_function_name($act_var);
            unless ($exp) {
                $exp = "waf_$func_name($combined_val)";
            }
            else {
                $exp = "waf_$func_name($exp)";
            }
        }
        if (! $exp) {
            return;
        }
        my $lua_var = get_lua_var_name();
        print "local $lua_var = $exp\n";
        set_exp $long_name, $lua_var;
    }
    return get_exp $long_name;
}

sub replace_var_inside {
    my ($expression, $var, $value) = @_;
    $var = quotemeta($var);
    $expression =~ s/%{$var}/$value/ig;
    return $expression;
}

sub replace_macros {
    my ($statement) = @_;
    my $hash;
    $hash->{MATCHED_VAR} = "waf_v['MATCHED_VAR']";
    $hash->{MATCHED_VAR_NAME} = "waf_v['MATCHED_VAR_NAME']";
    $hash->{'rule.msg'} = "waf_v['RULE:MSG']";
    $hash->{'rule.id'} = "waf_v['RULE:ID']";
    # replace %{tx.score} to waf_v["TX:SCORE"]
    while ($statement =~ /%{(tx\.(\w+))}/ig) {
        my ($var1, $var2) = ($1, $2);
        if($var2 =~ /^\d+$/) {
            $hash->{$var1} = 'waf_v_tx[' . uc($var2) . ']';
        }
        else {
            $hash->{$var1} = "waf_v['TX:" . uc($var2) . "']";
        }
    }
    for my $key (keys %$hash) {
        my $val = $hash->{$key};
        $statement = replace_var_inside($statement, $key, $val);
    }

    if ($statement =~ /(%{[^}]+})/) {
        croak "unknown variable $1 :", Dumper($hash);
    }

    return $statement;
}

# "%{a} foo %{b} bar" ==> %{a} .. " foo " .. %{b} .." bar"
sub convert_str {
    my ($right) = @_;
    my @result;
    my @list = split /(%{[^}]+})/, $right;
    for (my $i = 0; $i <= $#list; $i += 2) {
        $list[$i] = "'$list[$i]'";
    }
    return join " .. ", @list;
}

sub gen_param_expression {
    my ($act) = @_;
    my $str = $act->[1];
    # ignore this
    # tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/LDAP_INJECTION-%{matched_var_name}=%{tx.0}
    if ($str =~ /[^-]+-.*=.+/) {
        return;
    }
    # 'xxx' ==> xxx
    if ($str =~ /['\"]?([^'\"]+)/) {
        $str = $1;
    }
    #  CONVERT tx.sql_injection_score=+%{tx.critical_anomaly_score}  TO
    # %{tx.sql_injection_score} = %{tx.sql_injection_score} + %{tx.critical_anomaly_score}
    if ($str =~ /([^=]+)=\+(\S+)/) {
        $str = "%{$1} = %{$1} and (%{$1} + $2) or $2";
    }
    # CONVERT tx.sqli_select_statement=%{tx.sqli_select_statement} %{matched_var} TO
    # %{tx.sqli_select_statement}=%{tx.sqli_select_statement} .. %{matched_var}
    elsif ($str =~ /([^=]+)=(.+)/ && $act->[2] == ACT_HAVE_STR_VAR) {
        my ($right, $left) = ($1, $2);
        if ($left =~ /%{$right}/) {
            $str = "if %{$right} == nil then %{$right} = '' end %{$right}=" . convert_str($left);
        }
        else {
            $str = "%{$right}=" . convert_str($left);
        }
    }
    elsif ($act->[2] == ACT_HAVE_STR_VAR) {
        $str = convert_str($str);
    }

    $str = replace_macros($str);

    return $str;
}

sub act_sort_func {
    my %priority = ( block => 1,
                     skipAfter => 2);
    my $ap = ($priority{$a->[0]}) || 0;
    my $bp = ($priority{$b->[0]}) || 0;
    $ap <=> $bp;
}

sub generate_acts {
    my ($acts) = @_;
    my %ignore = ( t      => 1, tag    => 1,
                   capture=> 1, rev    => 1,
                   ver    => 1, ctl    => 1,
                   chain  => 1);
    # 为了让block操作和skipAfter操作最后执行，进行action排序
    my @sorted = sort act_sort_func  @$acts;
    # ignore t:xxx because t:xxx have been done by transform_vars()
    my @list = grep { !exists $ignore{$_->[0]} && !is_attribute($_->[0]) } @sorted;
    for my $act (@list) {
        my $act_op = $act->[0];
        my $act_var = $act->[1];
        # TODO: ajust code according phase
        if ($act_op eq "setvar") {
            print gen_param_expression($act), "\n";
        }
        elsif ($act_op eq 'id' || $act_op eq 'msg') {
            print "waf_v['RULE:", uc($act_op),"']=",  gen_param_expression($act), "\n";
        }
        elsif ($act_op eq "skipAfter") {
            print "goto $act_var\n";
        }
        elsif($act_op eq 'block') {
            print "waf_block(waf_v)\n";
        }
        elsif ($waf_act->is_supported($act_op) ) {
            $act_var = $act_var && gen_param_expression($act);
            print "waf_$act_op($act_var)\n";
        }
        else {
            print LOG "act_op: $act_op is not suppored\n";
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
my %number_op = (eq => "==", ge => ">=", le => "<=",
                 gt => ">", lt => "<", ne=> "~=" );
sub generate_if_statement {
    my ($lua_var, $rule_op) = @_;
    my ($op, $op_param, $op_is_negtive) = @$rule_op;
    if ($op eq 'streq') {
        print "matched = ( $lua_var == \"$op_param\" )\n";
    }
    elsif(exists $number_op{$op}) {
        print "matched = ( $lua_var ~= nil and $lua_var $number_op{$op} $op_param)\n";
    }
    else {
        # 处理 '@beginWiths %{request_header.host}'的情况
        if ($op_param =~ /%{([a-zA-Z_]+)\.([a-zA-Z_]+)}/) {
            my %single_arg = ( $1 => [ $2 ] );
            my $r = get_single_args(\%single_arg, 1);
            $op_param = $r->[0]->[1]; # $var_name
            print "matched, matched_name = waf_${op}($lua_var, $op_param)\n";
        }
        else {
            $op_param =~ s/\\(?!")/\\\\/g if $op eq 'rx';
            print "matched, matched_name = waf_${op}($lua_var, \"$op_param\")\n";
        }
    }
    if ($op_is_negtive) {
        print "if not matched then\n";
    }
    else {
        print "if matched then\n";
    }
    if ($op eq 'rx' || $op eq 'pm' || $op eq 'pmFromFile') {
        print "waf_v['MATCHED_VAR_NAME'] = matched_name\n";
        print "waf_v['MATCHED_VAR'] = matched[0]\n";
        print "waf_v_tx = matched\n";
    }
}

sub generate_end_if {
    print "end\n";
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

    if ($in_recurrence) {
        local %GLOBAL_VAR = ();
        local %GLOBAL_EXP = ();
        local %CACHED_EXP = ();
    }

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
        if (! $waf_op->is_supported($op) &&
            ! exists $number_op{$op} &&
            $op ne 'streq') {
            printf LOG "op: $op not suppported\n";
            next;
        }

        my $list = generate_vars($var);
        next unless $list;

        my $not_combine = exists $number_op{$op} && $list->[0];

        my $combined_var = combine_vars($list, $not_combine);

        my $lua_var = transform_vars($combined_var, $rule->{act});
        if (!$lua_var) {
            next;
        }
        generate_if_statement($lua_var, $rule->{op});

        my @disruptive = grep { is_act_disruptive $_->[0] } @{ $rule->{act} };
        my @non_disruptive = grep { !is_act_disruptive $_->[0] } @{ $rule->{act} };
        if ($rule->{chain}) {
            generate_acts \@non_disruptive;
            my $chained_rule = $rule->{chain};
            for my $a (keys %ATTRIBUTE) {
                $chained_rule->{$a} = $rule->{$a} unless $chained_rule->{$a};
            }
            # todo 变量在嵌套if中变成局部可见了
            $in_recurrence = 1;
            generate([ $rule->{chain} ]);
            $in_recurrence = 0;
            generate_acts \@disruptive;
        }
        else {
            generate_acts $rule->{act};
        }
        generate_end_if();
    }
}

$/=undef;
my $str = <>;
$waf_trans->gen_code;
$waf_op->gen_code;
$waf_act->gen_code;
print "local waf_var = require 'waf_var'\n";
print "local waf_v = {}\n";
my $result = parse($str);
#print Dumper($result);
generate($result);
