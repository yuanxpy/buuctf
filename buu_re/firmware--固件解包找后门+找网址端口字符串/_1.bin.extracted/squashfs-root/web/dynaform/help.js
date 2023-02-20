var window_width = 502;

function dohelp()
{
	var window_title = arguments[0];
	var window_height = 190;
	if (arguments.length >= 2)
	{
		window_height = arguments[1];
	}
	if (arguments.length >= 3)
	{
		window_width = arguments[2];
	}
	var title_width = window_width - 7;
	var table_width = window_width - 2;
	
	document.write('<CENTER>');
	document.write('<FORM action=\"#\" enctype=\"multipart\/form-data\" method=\"get\">');
	document.write('<TABLE width=\"' + window_width + '\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">');
	document.write('<TR><TD width=\"7\" class=\"title\"><img src=\"..\/images\/arc.gif\" width=\"7\" height=\"24\"><\/TD>');
	document.write('<TD width=\"' + title_width + '\" align=\"left\" valign=\"middle\" class=\"title\">' + window_title + '<\/TD><\/TR>');
	document.write('<TR><TD colspan=\"2\"><TABLE width=\"' + window_width + '\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\"><TR><TD class=\"vline\" rowspan=\"15\"><br><\/TD><TD width=\"' + table_width + '\" height=\"'  + window_height + '\">');
}

function done()
{
	document.write('<\/TD><TD class=\"vline\" rowspan=\"15\"><BR><\/TD><\/TR>');
	document.write('<TR><TD class=\"hline\"><img src=\"..\/images\/empty.gif\" width=\"1\" height=\"1\"><\/TD><\/TR>');
	document.write('<TR><TD height=\"30\" class=\"tail\">&nbsp;&nbsp;<input name=\"back\" type=\"button\" class=\"button\" onClick=\"doPrev();\" value=\"·µ »Ø\"><\/TD><\/TR>');
	document.write('<TR><TD class=\"hline\"><img src=\"..\/images\/empty.gif\" width=\"1\" height=\"1\"><\/TD><\/TR><\/TABLE><\/TD><\/TR><\/TABLE><\/FORM><\/CENTER>');	
}

function blank()
{
	document.write('<TR><TD>&nbsp</TD></TR>');
}


function writeline()
{
	var argc = arguments.length;
	var left_width =  (window_width - 502) + 150;
	var right_width = window_width - 42 - left_width;
	switch (argc)
	{
	case 1:		
		document.write('<TR><TD colspan=\"1\" width="900">' + arguments[0] + '<\/TD><\/TR>');	
		break;
	case 2:
		document.write('<tr><td width=\"' + left_width + '\" class=\"top\">' + arguments[0] + '</td><td width = \"' + right_width + '\">' + arguments[1] + '</td></tr>');
		break;
	case 3:
		//var rest = 466 - arguments[2];
		//document.write('<tr><td width=\"¡® + arguments[2] + ¡¯\" class=\"top\">' + arguments[0] + '</td><td width=\"' + rest + '\">' + arguments[1] + '</td></tr>');
		//break;
	default:
		break;
	}
}

function begin()
{
	var table_width = window_width - 50;
	document.write('<TABLE width=\"' + table_width + '\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" class=\"space\">');
}

function end()
{
	document.write('<\/TABLE>');
}
