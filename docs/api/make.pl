#!/usr/bin/perl
#
# prosty skrypt tworzący dokumentację API libgadu z dostępnych źródeł.
#
# $Id$

open(H, ">ref.functions.html");

print H "<html>\n<head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=iso-8859-2\">\n<link rel=stylesheet href=\"ref.css\" type=\"text/css\">\n</head>\n<body>\n";

for $i (glob("../../lib/*.c")) {
	open(F, $i);

	print "Plik $i\n";

	while (<F>) {
		chomp();
		next if (!/^\/\*/);

		$_ = <F>;
		chomp();
		next if (!/^ \* gg_.*\(\)/);

		s/^ \* //;
		s/\(.*//;

		$name = $_;
		print "  Funkcja $name\n";
		$descr = "";
		$p_num = 0;
		%p_descr = ();
		%p_type = ();
		$result = "";
		
		<F>;
		
		while (1) {
			# wczytaj linię.
			$_ = <F>;
			chomp();

			# usuń komentarz.
			s/^ \* *//;
			
			# jeśli zaczęły się parametry, spadaj.
			last if (/^-/ || /^\/$/);
			
			if (/^$/) {
				$descr .= "<p> ";
			} else {
				$descr .= "$_ ";
			}
		}

		$descr =~ s/<p> $//;

		$descr = uc_my($descr);

		while (1) {
			# jeśli koniec parametrów, wyjdź.
			last if (/^$/ || /^\/$/);

			# początek opisu parametru?
			if (/^- ([^ -]+) - (.*)/) {
				$last_p = "$p_num $1";
				$p_descr{$last_p} = $2;
				$p_num++;
			} elsif (/^- ([a-zA-Z0-9_]+)/) {
				$last_p = "$p_num $1";
				$p_descr{$last_p} = "";
				$last_p = $1;
			} else {
				$p_descr{$last_p} .= "$_ ";
			}

			# czytaj następną linię.
			$_ = <F>;
			chomp();
			s/^ \* *//;
		}

		while (!/^\/$/) {
			if ($_ ne "") {
				$result .= "$_ ";
			}

			$_ = <F>;
			chomp();
			s/^ \* *//;
		}

		if (!$result) {
			$result = "Brak.";
		}

		if ($result =~ /0, -1, errno/) {
			$result = "0 jeśli operacja się powiodła, -1 w przypadku błędu (kod błędu w zmiennej <tt>errno</tt>.)";
		}
		if ($result =~ /0, -1/) {
			$result = "0 jeśli operacja się powiodła, -1 w przypadku błędu.";
		}

		$result = uc_my($result);

		$_ = <F>;
		chomp();

		next if (/^static/);
		
		$decl = $_;
		
		s/^[^(]*\(//;
		s/\) *$//;

		foreach (split(/ *, */)) {
			s/^ *//;
			s/ *$//;

			if (/([a-zA-Z0-9_]+)$/) {
				$p_name = $1;
				$_ =~ s/$p_name$//;
				$p_type{$p_name} = $_;
			}
		}

		print H "<a name=\"$name\">\n";
		print H "<div class=func>\n$name\n</div>\n";
		print H "<div class=header>\nDziałanie:\n</div>\n";
		print H "<div class=desc>\n$descr\n</div>\n";

		$decl = declarize($decl);

		$functions{$name} = declarize2($decl);

		print H "<div class=header>\nDeklaracja:\n</div>\n";
		print H "<div class=decl>\n$decl;\n</div>\n";

		if (%p_descr) {
			print H "<div class=header>\nParametry:\n</div>\n";
			print H "<div class=params>\n<table cellspacing=1 border=0 class=params>\n";
			
			foreach $i (sort keys %p_descr) {
				$name = $i;
				$name =~ s/^[0-9]* //g;
				$name2 = $name;
				$name2 =~ s/\.\.\.$//;
				$type = colorize($p_type{$name2});
				print H "<tr><td class=paramname>$type<i>$name</i></td><td class=paramdescr>" . $p_descr{$i} . "</td></tr>\n";
			}
		}

		print H "</table>\n</div>\n";
		print H "<div class=header>\nZwracana wartość:\n</div>\n";
		print H "<div class=result>\n$result\n</div>\n";
	}

	close(F);
	
}

print H "</body>\n</html>\n";
close(H);

open(F, "functions.txt");

open(H, ">ref.html");
print H "<html>\n<head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=iso-8859-2\">\n<link rel=stylesheet href=\"ref.css\" type=\"text/css\">\n</head>\n<body>\n";

$first = 1;

while(<F>) {
	chomp;

	next if (/^[\t ]*$/);

	if (/^[A-Z]/) {
		if (!$first) {
			print H "</div>\n";
		}
		$first = 0;
		print H "<div class=\"funcgroup\">$_</div>\n";
		print H "<div class=\"indexdecl\">\n";
	}

	if (/^\t(.*)/) {
		print H $functions{$1}, ";<br>\n";
	}
}

print H "</body>\n</html>\n";

close(F);
close(H);


sub uc_char($)
{
	my ($ch) = @_;

	$ch =~ y/a-ząćęłńóśżź/A-ZĄĆĘŁŃÓŚŻŹ/;

	return $ch;
}

sub uc_my()
{
	my ($str) = @_;

	$str =~ s/ +/ /g;

	$str =~ s/^(.)/uc_char($1)/eg;
	$str =~ s/\. ([a-ząćęłńóśżź])/sprintf(". %s", uc_char($1))/eg;
	$str =~ s/\"([^"]*)\"/"<tt>$1<\/tt>"/g;
	$str =~ s/\'([^']*)\'/'<tt>$1<\/tt>'/g;
	$str =~ s/([a-zA-Z0-9_]+\(\))/<tt>$1<\/tt>/g;
	$str =~ s/(gg_[a-zA-Z0-9_]+)\(\)/<a href="#$1">$1()<\/a>/g;
	$str =~ s/(GG_[A-Z0-9_]+)/<tt>$1<\/tt>/g;
	$str =~ s/NULL/<tt>NULL<\/tt>/g;

	return $str;
}

sub space_to_dash($)
{
	$_ = $_[0];

	y/ /_/;

	return $_;
}

sub colorize($)
{
	$_ = $_[0];

	@ctypes = qw(void char long short u?int[0-9]+_t int);
	push @ctypes, "struct hostent";
	push @ctypes, "struct in_addr";
	foreach $i (@ctypes) {
		s/(inline |const |static |unsigned )*($i)/<span class=\"ctype\">$1$2<\/span>/g;
	}

	$known[0] = "struct gg_[0-9a-z_]+";
	$known[1] = "uin_t";
	foreach $i (@known) {
		$type = $i;
		$type =~ s/ /_/g;
		s/(const )*($i)/sprintf("<a class=\"typelink\" href=\"ref.types.html#%s\">%s%s<\/a>", space_to_dash($2), $1, $2)/eg;
	}

	return $_;
}

sub declarize()
{
	my $result, $params, $nam, $type, ($decl) = @_;

	$params = $decl;
	$params =~ s/[^(]*\(//;
	$params =~ s/\).*//;

	$nam = $decl;
	$nam =~ s/\(.*//;
	$nam =~ s/.*(gg_[a-z0-9_]+)/$1/;

	$type = $decl;
	$type =~ s/gg_[a-z0-9_]+\(.*//;

	$result = colorize($type) . "<b>$nam</b>(";

	foreach (split(/ *, */, $params)) {
		s/^ *//;
		s/ *$//;

		if (/([a-zA-Z0-9_]+)$/) {
			$nam = $1;
			$_ =~ s/$nam$//;
			$result .= colorize($_) . "<i>$nam</i>, ";
		} elsif (/^\.\.\.$/) {
			$result .= "<i>...</i>";
		}
	}

	$result =~ s/, $//;
	$result .= ")";

	return $result;
}

sub declarize2()
{
	my ($str) = @_;

	$str =~ s/<a [^>]*>/<span class=\"ggtype\">/g;
	$str =~ s/<\/a>/<\/span>/g;

	$str =~ s/<b>([^<]*)<\/b>/<b><a class=\"funclink\" href=\"ref.functions.html#$1\">$1<\/a><\/b>/g;

	return $str;
}

